"""
Balance detection CSV: undersample majority (malign) + oversample minority (benign)
to reach the same count per class (50/50).

Reads a CSV with columns: command, label (0=benign, 1=malign).
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


def load_rows(path: Path) -> tuple[list[str], list[str]]:
    benign: list[str] = []
    malign: list[str] = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "command" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("CSV must have header: command,label")
        for row in reader:
            cmd = (row.get("command") or "").strip()
            if not cmd:
                continue
            lab = str(row.get("label", "")).strip()
            if lab == "0":
                benign.append(cmd)
            elif lab == "1":
                malign.append(cmd)
    return benign, malign


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Balance classes: undersample malign + oversample benign to target size."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=root / "data" / "processed" / "detection_train_benign_malign_cleaned.csv",
        help="Unbalanced CSV from build_detection_csv.py (cleaned merge).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "processed" / "detection_train_balanced.csv",
        help="Balanced CSV output path.",
    )
    parser.add_argument(
        "--target-per-class",
        type=int,
        default=None,
        metavar="N",
        help="Rows per class (capped by malign count). If omitted: min(50000, malign_count) so benign is oversampled when needed.",
    )
    parser.add_argument(
        "--minority-only",
        action="store_true",
        help="Balance to min(benign,malign) only: no benign oversampling, more malign discarded.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="RNG seed for reproducible sampling.",
    )
    args = parser.parse_args()
    rng = random.Random(args.seed)

    benign, malign = load_rows(args.input)
    n_b, n_m = len(benign), len(malign)
    if n_b == 0 or n_m == 0:
        raise ValueError(f"Need both classes non-empty; got benign={n_b}, malign={n_m}")

    if args.minority_only:
        target = min(n_b, n_m)
        requested_desc = f"--minority-only min(benign,malign)={target}"
    elif args.target_per_class is None:
        target = min(50_000, n_m)
        requested_desc = f"default min(50000,malign_count)={target}"
    else:
        target = min(args.target_per_class, n_m)
        requested_desc = str(args.target_per_class)
    if target < 1:
        raise ValueError("target-per-class must be >= 1")

    malign_sample = rng.sample(malign, target)

    if target <= n_b:
        benign_sample = rng.sample(benign, target)
    else:
        benign_sample = rng.choices(benign, k=target)

    rows = [(c, 0) for c in benign_sample] + [(c, 1) for c in malign_sample]
    rng.shuffle(rows)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as out:
        w = csv.writer(out)
        w.writerow(["command", "label"])
        w.writerows(rows)

    print(f"Wrote {args.output}")
    print(f"  input: benign={n_b}, malign={n_m}")
    print(f"  target per class: {target} (requested: {requested_desc}; capped by malign count)")
    print(f"  output rows: {len(rows)} (expected {2 * target})")
    if target < n_b:
        benign_mode = "undersample (no replacement)"
    elif target == n_b:
        benign_mode = "all benign samples (no replacement)"
    else:
        benign_mode = "oversample with replacement"
    print(f"  benign: {benign_mode}")
    print(f"  malign: undersample")
    print(f"  seed: {args.seed}")


if __name__ == "__main__":
    main()
