from pathlib import Path

marker = "Base code: latest prototype tree (UDP inline-ACK line);"
add = (
    "The README status snapshot describes the prior prototype build; the hashes "
    "and verification in this file apply to this candidate."
)
for name in ("RC-NOTES.md", "pkg/docs/RC-NOTES.md"):
    p = Path(name)
    s = p.read_text()
    if add in s:
        continue
    line = next(l for l in s.splitlines() if l.startswith(marker))
    s = s.replace(line, line + "\n" + add, 1)
    p.write_text(s)
    print("updated", name)