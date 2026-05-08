# AI-CMD-Assistant

# Task 1 – Malicious / Benign Command Classifier

## Overview

This task builds a **hybrid detection system** that classifies Unix/Linux shell commands as either **BENIGN** or **MALICIOUS**.  
The system combines:

- **Hard‑coded regex rules** – instant, deterministic detection of high‑risk patterns (e.g., `kill -9 -1`, `sudo su -`, disk destruction, history wiping).
- **Fine‑tuned DistilBERT transformer** – learns patterns from a large, balanced dataset of real and synthetic commands.

The model achieves **>99% accuracy** on a held‑out test set and handles a wide variety of malicious behaviours (reverse shells, privilege escalation, data exfiltration, crypto mining, etc.).

---

## Dataset

### Source & Balance

- Original balanced dataset: **50,000 benign + 50,000 malicious** commands.
- Benign commands originate from the NL2Bash dataset plus manual additions.
- Malicious commands were expanded using **10 synthetic categories** (sensitive file access, destructive, download+execute, privilege escalation, cover tracks, network scan, persistence, exfiltration, disable security, crypto mining).

### Iterative Enrichment

After initial training, we identified **false positives** (e.g., `systemctl status ssh` flagged as malicious) and **false negatives** (e.g., `dd if=/dev/zero of=/dev/sda` flagged benign).  
We iteratively added:

- Missing benign commands (`pwd`, `systemctl status ssh`, `arpa`, `make clean`, etc.).
- Malicious command variants (`sudo su -`, `chmod 4777 /bin/bash`, `git clone + compile`, docker container escape, etc.).
- Reinforced overlapping patterns to avoid overfitting.

Final dataset: **~101,000 rows** (train 80k, val 10k, test 10k) with **no duplicate bias**.

---

## Model Training

- **Architecture**: `distilbert-base-uncased` with a binary classification head.
- **Training**: 1 epoch, batch size 32, learning rate 2e-5, FP16 (GPU T4 on Kaggle).
- **Input truncation**: 128 tokens (covers mean command length 45–123 characters).
- **Software**: Hugging Face Transformers, PyTorch, Kaggle GPU environment.

### Training Performance

| Split       | Accuracy | F1 Score | Loss   |
|-------------|----------|----------|--------|
| Validation  | 0.9993   | 0.9993   | 0.0040 |
| Test        | 1.0000   | 1.0000   | –      |

---

## Evaluation Results (Sample)

After the final augmentation, the model correctly classifies all challenging commands:

| Command                                 | Prediction | Confidence |
|-----------------------------------------|------------|------------|
| `sudo su -`                             | MALICIOUS  | 98.0%      |
| `chmod 4777 /bin/bash`                  | MALICIOUS  | 100%       |
| `kill -9 -1`                            | MALICIOUS  | 99.9%      |
| `dd if=/dev/zero of=/dev/sda bs=1M`    | MALICIOUS  | 99.0%      |
| `git clone ... && cd repo && make`      | MALICIOUS  | 99.7%      |
| `docker run -it --rm -v /:/mnt alpine chroot /mnt /bin/bash` | MALICIOUS | 99.9% |
| `history -c`                            | MALICIOUS  | 99.9%      |
| `systemctl status ssh`                  | BENIGN     | 99.6%      |
| `pwd`                                   | BENIGN     | 98.7%      |
| `ls -la`                                | BENIGN     | 99.8%      |

All 50+ test commands (benign and malicious) are now correctly labelled.

---

## Final Hybrid System

The production detector (`risk_detector.py`) works in two stages:

1. **Hard‑coded rules** (regex) – catch critical patterns that the model might miss (e.g., `kill -9 -1`, `sudo su -`, fork bomb).  
   → Returns `MALICIOUS` with confidence 1.0 and a descriptive reason.

2. **DistilBERT fine‑tuned model** – processes all other commands.  
   → Returns `MALICIOUS`/`SAFE` with a confidence score (0‑1) and reason "Model detection".

### Example usage

```python
from risk_detector import predict_risk

label, confidence, reason = predict_risk("sudo su -")
# label = "MALICIOUS", confidence = 1.0, reason = "Rule match: Privilege escalation to root shell"

# Note for Task 2 : 

task 2 needs a file that follows the dame logic used in risk_model.py so we could create the shell 