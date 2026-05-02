#!/usr/bin/env python3
import re
import sys
from pathlib import Path


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")


def extract_tag(html: str, tag: str) -> tuple[str, str]:
    m = re.search(
        rf"<{tag}\b[^>]*>([\s\S]*?)</{tag}>",
        html,
        flags=re.IGNORECASE,
    )
    if not m:
        die(f"could not find <{tag}> block")

    full = m.group(0)
    body = m.group(1).strip("\n")
    return full, body


def find_const_template_literal(src: str, const_name: str) -> tuple[int, int, str] | None:
    """
    Finds:

        const NAME = `...`;

    Returns:
        start offset of declaration,
        end offset after semicolon,
        raw template-literal body.
    """
    needle = f"const {const_name}"
    decl = src.find(needle)
    if decl < 0:
        return None

    eq = src.find("=", decl)
    if eq < 0:
        die(f"malformed declaration for {const_name}")

    tick0 = src.find("`", eq)
    if tick0 < 0:
        die(f"declaration {const_name} is not a template literal")

    i = tick0 + 1
    while i < len(src):
        ch = src[i]

        # Skip escaped chars inside the JS template literal.
        if ch == "\\":
            i += 2
            continue

        if ch == "`":
            tick1 = i
            semi = src.find(";", tick1 + 1)
            if semi < 0:
                semi = tick1

            body = src[tick0 + 1:tick1].strip("\n")
            return decl, semi + 1, body

        i += 1

    die(f"unterminated template literal for {const_name}")


def replace_const_template_literal(
    src: str,
    const_name: str,
    placeholder: str,
) -> tuple[str, str | None]:
    found = find_const_template_literal(src, const_name)
    if found is None:
        print(f"warning: {const_name} not found", file=sys.stderr)
        return src, None

    start, end, body = found
    repl = f"const {const_name} = {placeholder};"
    return src[:start] + repl + src[end:], body


def main() -> None:
    input_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("index.html")
    if not input_file.exists():
        die(f"input file not found: {input_file}")

    html = input_file.read_text(encoding="utf-8")

    src_dir = Path("src")
    css_dir = src_dir / "css"
    js_dir = src_dir / "js"
    workers_dir = src_dir / "workers"

    style_full, style_body = extract_tag(html, "style")
    script_full, script_body = extract_tag(html, "script")

    main_js = script_body

    main_js, single_worker = replace_const_template_literal(
        main_js,
        "WORKER_SRC",
        "__INLINE_WORKER_SINGLE__",
    )
    if single_worker is not None:
        write_text(workers_dir / "single-worker.js", single_worker + "\n")

    main_js, pool_worker = replace_const_template_literal(
        main_js,
        "WORKER_POOL_SRC",
        "__INLINE_WORKER_POOL__",
    )
    if pool_worker is not None:
        write_text(workers_dir / "pool-worker.js", pool_worker + "\n")

    html_template = html.replace(
        style_full,
        "<style>\n{{CSS_MAIN}}\n</style>",
        1,
    ).replace(
        script_full,
        "<script>\n{{JS_BUNDLE}}\n</script>",
        1,
    )

    write_text(src_dir / "index.template.html", html_template)
    write_text(css_dir / "main.css", style_body + "\n")
    write_text(js_dir / "app.js", main_js + "\n")

    print()
    print("Split complete.")
    print()
    print("Next:")
    print("  python3 tools/build-onefile.py")
    print("  open dist/index.html")


if __name__ == "__main__":
    main()
