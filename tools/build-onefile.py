#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        die(f"missing file: {path}")
    return path.read_text(encoding="utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    src = Path("src")
    dist = Path("dist")
    dist.mkdir(parents=True, exist_ok=True)

    template = read_text(src / "index.template.html")
    css = read_text(src / "css" / "main.css")
    js = read_text(src / "js" / "app.js")

    single_worker = read_text(src / "workers" / "single-worker.js")
    pool_worker = read_text(src / "workers" / "pool-worker.js")

    # json.dumps() creates a valid JS string literal.
    # This is safer than raw backticks because worker code may contain backticks,
    # ${...}, backslashes, and newlines.
    js = js.replace(
        "__INLINE_WORKER_SINGLE__",
        json.dumps(single_worker),
    ).replace(
        "__INLINE_WORKER_POOL__",
        json.dumps(pool_worker),
    )

    html = template.replace(
        "{{CSS_MAIN}}",
        css,
    ).replace(
        "{{JS_BUNDLE}}",
        js,
    )

    out = dist / "index.html"
    out.write_text(html, encoding="utf-8")

    raw = html.encode("utf-8")
    print(f"built {out}")
    print(f"sha256 {sha256_hex(raw)}")
    print(f"bytes {len(raw)}")


if __name__ == "__main__":
    main()
