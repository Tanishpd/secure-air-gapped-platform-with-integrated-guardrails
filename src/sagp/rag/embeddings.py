"""Local embeddings: BAAI/bge-small-en-v1.5 under ONNX Runtime.

This checkpoint is **CLS pooling** (``last_hidden_state[:, 0, :]``) then L2
normalize — NOT mean pooling, which produces plausible vectors and silently
halves recall (forbidden idea). 384-dim, cosine distance. The query prefix is
applied to queries only. ``token_type_ids`` is required (bge is a BERT model);
the feed is built from ``get_inputs()`` and zero-filled for it.

The M1 provisioning gate validated this ORT+CLS+L2 path against
``sentence-transformers`` to atol 1e-4 (measured 1.6e-7).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


class BgeEmbedder:
    MODEL_ID = "BAAI/bge-small-en-v1.5"
    DIM = 384

    def __init__(
        self,
        model_path: Path,
        tokenizer_path: Path,
        *,
        revision: str,
        max_length: int = 512,
    ) -> None:
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 4
        opts.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(
            str(model_path), sess_options=opts, providers=["CPUExecutionProvider"]
        )
        self._input_names = {i.name for i in self._sess.get_inputs()}
        self._tok = Tokenizer.from_file(str(tokenizer_path))
        self._tok.enable_truncation(max_length=max_length)
        self._tok.enable_padding()  # pad to the longest in each batch
        self.revision = revision
        self.max_length = max_length

    def embed(self, texts: list[str], *, is_query: bool) -> np.ndarray:
        """Return an (n, 384) array of L2-normalized CLS embeddings."""
        if not texts:
            return np.empty((0, self.DIM), dtype=np.float32)
        prepared = [QUERY_PREFIX + t for t in texts] if is_query else list(texts)
        encs = self._tok.encode_batch(prepared)
        input_ids = np.array([e.ids for e in encs], dtype=np.int64)
        attention = np.array([e.attention_mask for e in encs], dtype=np.int64)
        feed = {
            "input_ids": input_ids,
            "attention_mask": attention,
            "token_type_ids": np.zeros_like(input_ids),
        }
        feed = {k: v for k, v in feed.items() if k in self._input_names}
        last_hidden = self._sess.run(None, feed)[0]  # (n, seq, 384)
        cls = last_hidden[:, 0, :]  # CLS pooling — NOT mean
        norms = np.linalg.norm(cls, axis=1, keepdims=True)
        normed: np.ndarray = (cls / np.clip(norms, 1e-12, None)).astype(np.float32)
        return normed

    def embed_one(self, text: str, *, is_query: bool) -> np.ndarray:
        vec: np.ndarray = self.embed([text], is_query=is_query)[0]
        return vec
