from pathlib import Path

marker = "predecessor build, not to this artifact."
add = (
    "Go comparison: the only direct Go-vs-Rust performance comparison in the reports "
    "is the 4096-byte UDP review, and it used the predecessor binary. The RC test suite "
    "validates eight Go-generated protocol fixtures (`tests/fixtures/go-protocol.json`), "
    "but no side-by-side functional run of the Go daemon against this RC was performed."
)
for name in ("RC-NOTES.md", "pkg/docs/RC-NOTES.md"):
    p = Path(name)
    s = p.read_text()
    if add in s:
        continue
    idx = s.index(marker) + len(marker)
    s = s[:idx] + "\n" + add + s[idx:]
    p.write_text(s)
    print("updated", name)