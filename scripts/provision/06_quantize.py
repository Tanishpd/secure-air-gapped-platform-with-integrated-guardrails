"""06 — INT8-quantize the injection classifier ONNX model.

Dynamic quantization with the DEFAULT op set (do NOT pass op_types_to_quantize —
Gather is already covered; narrowing it was the bug the eval caught). Output goes
to models/derived/injection-int8/model.onnx and is parity-gated by 07.
"""

from __future__ import annotations

import shutil

from _common import ROOT, die, human, log

STEP = "06_quantize"


def main() -> int:
    from onnxruntime.quantization import QuantType, quantize_dynamic

    src = ROOT / "models" / "hf" / "injection" / "onnx" / "model.onnx"
    if not src.exists():
        die(STEP, f"missing {src} — run 02_hf_models first")

    out_dir = ROOT / "models" / "derived" / "injection-int8"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "model.onnx"

    # DeBERTa-v3 ships tokenizer/config beside the ONNX; copy them so the INT8
    # dir is a self-contained model the runtime can load with one path.
    for name in (
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
        "added_tokens.json",
        "spm.model",
    ):
        p = src.parent / name
        if p.exists():
            shutil.copy2(p, out_dir / name)

    log(STEP, f"quantize_dynamic (QInt8, default op types) {src.name} -> {out}")
    quantize_dynamic(
        model_input=str(src),
        model_output=str(out),
        weight_type=QuantType.QInt8,
    )
    if not out.exists():
        die(STEP, "quantization produced no output")
    log(STEP, f"fp32 {human(src.stat().st_size)} -> int8 {human(out.stat().st_size)}")
    log(STEP, "done (parity + RSS gated by 07_gates.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
