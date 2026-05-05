"""
Build a single CSV for benign vs malicious command classification.

Labels: 0 = benign, 1 = malicious (malign).
Sources: nl2bash.cm (text, one command per line) + X_train_malicious_cmd_orig.json (JSON array of strings).

Cleaning : drop empties, dedupe (command, label), length < 2, control / garbage unicode.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from pathlib import Path

# Zero-width / bidi marks / BOM (noise in scraped text)
_GARBAGE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\ufeff\u2060-\u206f\ufeff]"
)


def clean_command(cmd: str) -> str | None:
    """Return cleaned command or None if it should be dropped."""
    if not isinstance(cmd, str):
        return None
    cmd = cmd.strip()
    if not cmd:
        return None
    cmd = cmd.replace("\x00", "")
    cmd = _GARBAGE_RE.sub("", cmd)
    # One line for CSV safety; internal newlines become space
    cmd = " ".join(cmd.split())
    out: list[str] = []
    for ch in cmd:
        cat = unicodedata.category(ch)
        if cat == "Cc" and ch != "\t":
            continue
        if cat == "Cs":
            continue
        out.append(ch)
    cmd = "".join(out).strip()
    if len(cmd) < 2:
        return None
    return cmd


def dedupe_preserve_order(rows: list[tuple[str, int]]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for cmd, lab in rows:
        key = (cmd, lab)
        if key in seen:
            continue
        seen.add(key)
        out.append((cmd, lab))
    return out


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Merge benign + malicious (orig train) into one CSV.")
    parser.add_argument(
        "--benign",
        type=Path,
        default=root / "data" / "benign_commands" / "nl2bash.cm",
        help="Text file: one shell command per line.",
    )
    parser.add_argument(
        "--malicious-json",
        type=Path,
        default=root / "data" / "malign_commands" / "X_train_malicious_cmd_orig.json",
        help="JSON array of malicious command strings (train orig only).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "processed" / "detection_train_benign_malign_orig.csv",
        help="Output CSV path (parent dirs are created if missing).",
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Skip cleaning/deduping (raw strip + non-empty only).",
    )
    args = parser.parse_args()

    benign_path: Path = args.benign
    mal_json: Path = args.malicious_json
    out_path: Path = args.output

    benign_raw = 0
    malign_raw = 0
    benign_rows: list[tuple[str, int]] = []
    if benign_path.is_file():
        with benign_path.open(encoding="utf-8", errors="replace", newline="") as f:
            for line in f:
                benign_raw += 1
                cmd = line.strip()
                if not cmd:
                    continue
                if args.no_clean:
                    benign_rows.append((cmd, 0))
                else:
                    cleaned = clean_command(cmd)
                    if cleaned is not None:
                        benign_rows.append((cleaned, 0))
    else:
        raise FileNotFoundError(benign_path)

    if not mal_json.is_file():
        raise FileNotFoundError(mal_json)
    with mal_json.open(encoding="utf-8") as f:
        malicious = json.load(f)
    if not isinstance(malicious, list):
        raise ValueError("Malicious JSON must be a JSON array of strings.")
    mal_rows: list[tuple[str, int]] = []
    for item in malicious:
        if not isinstance(item, str):
            continue
        malign_raw += 1
        if args.no_clean:
            cmd = item.strip()
            if cmd:
                mal_rows.append((cmd, 1))
        else:
            cleaned = clean_command(item)
            if cleaned is not None:
                mal_rows.append((cleaned, 1))

    if not args.no_clean:
        n_b_before = len(benign_rows)
        n_m_before = len(mal_rows)
        benign_rows = dedupe_preserve_order(benign_rows)
        mal_rows = dedupe_preserve_order(mal_rows)
        print(
            "  dedupe removed:",
            f"benign {n_b_before - len(benign_rows)},",
            f"malign {n_m_before - len(mal_rows)}",
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as out:
        w = csv.writer(out)
        w.writerow(["command", "label"])
        w.writerows(benign_rows)
        w.writerows(mal_rows)

    print(f"Wrote {out_path}")
    if not args.no_clean:
        print(f"  raw lines seen: benign file lines={benign_raw}, malign json items={malign_raw}")
    print(f"  benign (label=0): {len(benign_rows)}")
    print(f"  malign (label=1): {len(mal_rows)}")
    print("  label convention: 0=benign, 1=malign")
    if not args.no_clean:
        print("  cleaning: empty/short<2/controls/zero-width removed; duplicates removed per class")


if __name__ == "__main__":
    main()
