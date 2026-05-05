"""
Stratified 80% / 10% / 10% train-validation-test split on a balanced CSV.

Output: command, label, split  (split = train | validation | test)
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


def stratified_indices(labels: list[int], seed: int) -> tuple[list[int], list[int], list[int]]:
    """Return index lists for train, validation, test (disjoint, full coverage)."""
    rng = random.Random(seed)
    by_class: dict[int, list[int]] = {0: [], 1: []}
    for i, lab in enumerate(labels):
        by_class[int(lab)].append(i)

    train_idx: list[int] = []
    val_idx: list[int] = []
    test_idx: list[int] = []

    for lab in (0, 1):
        idxs = by_class[lab]
        rng.shuffle(idxs)
        n = len(idxs)
        n_train = (n * 80) // 100
        n_val = (n * 10) // 100
        n_test = n - n_train - n_val
        train_idx.extend(idxs[:n_train])
        val_idx.extend(idxs[n_train : n_train + n_val])
        test_idx.extend(idxs[n_train + n_val :])

    rng.shuffle(train_idx)
    rng.shuffle(val_idx)
    rng.shuffle(test_idx)
    return train_idx, val_idx, test_idx


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Stratified 80/10/10 split with split column.")
    parser.add_argument(
        "--input",
        type=Path,
        default=root / "data" / "processed" / "detection_train_balanced.csv",
        help="Balanced CSV (columns: command, label).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data" / "processed" / "task1_dataset.csv",
        help="Output CSV with command, label, split.",
    )
    parser.add_argument("--seed", type=int, default=42, help="RNG seed.")
    args = parser.parse_args()

    commands: list[str] = []
    labels: list[int] = []
    with args.input.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "command" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("Input CSV must have headers: command,label")
        for row in reader:
            cmd = (row.get("command") or "").strip()
            if not cmd:
                continue
            lab = int(str(row.get("label", "")).strip())
            commands.append(cmd)
            labels.append(lab)

    n = len(labels)
    if n == 0:
        raise ValueError("No rows in input.")

    train_idx, val_idx, test_idx = stratified_indices(labels, args.seed)
    split_by_index: dict[int, str] = {}
    for i in train_idx:
        split_by_index[i] = "train"
    for i in val_idx:
        split_by_index[i] = "validation"
    for i in test_idx:
        split_by_index[i] = "test"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as out:
        w = csv.writer(out)
        w.writerow(["command", "label", "split"])
        for i in range(n):
            w.writerow([commands[i], labels[i], split_by_index[i]])

    n_tr, n_va, n_te = len(train_idx), len(val_idx), len(test_idx)
    print(f"Wrote {args.output}")
    print(f"  input rows: {n}")
    print(f"  train: {n_tr} ({100 * n_tr / n:.2f}%)")
    print(f"  validation: {n_va} ({100 * n_va / n:.2f}%)")
    print(f"  test: {n_te} ({100 * n_te / n:.2f}%)")
    print(f"  seed: {args.seed}")


if __name__ == "__main__":
    main()
