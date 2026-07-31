"""ONNX Runtime backend for the injection classifier (the real ``Scorer``).

Runs the FP32 DeBERTa-v3 ONNX (INT8 rejected — OQ-2) on CPU with
``intra_op_num_threads=4, inter_op_num_threads=1`` (leaving four cores for
Ollama). The feed dict is built from ``sess.get_inputs()`` — never hardcoded —
because DeBERTa-v2 has ``type_vocab_size=0`` and so takes no ``token_type_ids``.

Long inputs are windowed at the token level (``max_length``/``stride``); each
window gets ``[CLS]…[SEP]`` and is scored, and the max P(INJECTION) is taken. If
the input needs more than ``max_windows`` windows it is ``truncated`` — the
scanner blocks, so the tail of a long attack can never slip past truncation.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from sagp.guardrails.injection.labels import resolve_injection_index
from sagp.guardrails.injection.scanner import WindowScore
from sagp.guardrails.policy import InjectionPolicy


def _softmax(logits: np.ndarray) -> np.ndarray:
    e = np.exp(logits - logits.max(axis=-1, keepdims=True))
    result: np.ndarray = e / e.sum(axis=-1, keepdims=True)
    return result


class OnnxInjectionScorer:
    def __init__(
        self,
        model_path: Path,
        tokenizer_path: Path,
        config_path: Path,
        policy: InjectionPolicy,
    ) -> None:
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 4
        opts.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(
            str(model_path), sess_options=opts, providers=["CPUExecutionProvider"]
        )
        self._input_names = {i.name for i in self._sess.get_inputs()}
        self._tok = Tokenizer.from_file(str(tokenizer_path))
        cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
        self._idx = resolve_injection_index(cfg["id2label"], policy.labels.positive_aliases)
        self._max_len = policy.window.max_length
        self._stride = policy.window.stride
        self._max_windows = policy.window.max_windows
        self._cls = self._tok.token_to_id("[CLS]")
        self._sep = self._tok.token_to_id("[SEP]")
        self._pad = self._tok.token_to_id("[PAD]") or 0

    def _windows(self, text: str) -> tuple[list[list[int]], int, bool]:
        """Return (windows of token ids incl special tokens, n_windows, truncated)."""
        enc = self._tok.encode(text)
        ids = enc.ids
        if len(ids) <= self._max_len:
            return [ids], 1, False
        # Strip the model's own [CLS]/[SEP] and re-window the content tokens.
        content = ids[1:-1] if self._cls is not None and self._sep is not None else ids
        span = self._max_len - 2  # room for [CLS] and [SEP]
        starts = list(range(0, max(1, len(content) - span + 1), self._stride))
        if starts and starts[-1] + span < len(content):
            starts.append(len(content) - span)  # ensure the tail is covered
        n = len(starts)
        truncated = n > self._max_windows
        windows: list[list[int]] = []
        for start in starts[: self._max_windows]:
            chunk = content[start : start + span]
            windows.append([self._cls or ids[0], *chunk, self._sep or ids[-1]])
        return windows, n, truncated

    def score_max(self, text: str) -> WindowScore:
        windows, n_windows, truncated = self._windows(text)
        batch = len(windows)
        input_ids = np.full((batch, self._max_len), self._pad, dtype=np.int64)
        attention = np.zeros((batch, self._max_len), dtype=np.int64)
        for i, w in enumerate(windows):
            input_ids[i, : len(w)] = w
            attention[i, : len(w)] = 1
        feed = {"input_ids": input_ids, "attention_mask": attention}
        feed = {k: v for k, v in feed.items() if k in self._input_names}
        logits = self._sess.run(None, feed)[0]
        probs = _softmax(np.asarray(logits))
        max_score = float(probs[:, self._idx].max())
        return WindowScore(max_score=max_score, n_windows=n_windows, truncated=truncated)
