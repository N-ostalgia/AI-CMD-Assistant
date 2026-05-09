# suggest_model.py — GPT-2 Next Command Predictor

import torch
from transformers import GPT2Tokenizer, GPT2LMHeadModel

# ── Load model ────────────────────────────────────────────────────────────────
MODEL_PATH = "./models/gpt2_bash_next_model"

tokenizer = GPT2Tokenizer.from_pretrained(MODEL_PATH)
tokenizer.pad_token = tokenizer.eos_token

model  = GPT2LMHeadModel.from_pretrained(MODEL_PATH)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = model.to(device)
model.eval()

SEP         = "<CMD>"
_history    = []
MAX_HISTORY = 3


def predict_next(command: str) -> str:
    """
    Takes current command, returns predicted next command as string.
    Automatically tracks history of last 3 commands.
    """
    global _history

    _history.append(command.strip())
    if len(_history) > MAX_HISTORY:
        _history = _history[-MAX_HISTORY:]

    input_text = (f" {SEP} ").join(_history) + f" {SEP} "

    try:
        inputs = tokenizer(
            input_text,
            return_tensors="pt",
            padding=True,
            return_attention_mask=True
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model.generate(
                inputs["input_ids"],
                attention_mask=inputs["attention_mask"],  # ← fixes warning
                max_new_tokens=15,
                num_return_sequences=1,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id,
            )

        full_text = tokenizer.decode(outputs[0], skip_special_tokens=False)
        parts     = full_text.split(SEP)
        next_cmd  = parts[-1].split("<|endoftext|>")[0].strip()
        next_cmd  = next_cmd.split("\n")[0].strip()

        if not _is_good_suggestion(next_cmd, command):
            return _fallback(command)

        return next_cmd

    except Exception:
        return _fallback(command)


def reset_history():
    """Call this to clear history on new session."""
    global _history
    _history = []


def _is_good_suggestion(suggestion: str, current_command: str) -> bool:
    """Filter out bad suggestions."""
    if not suggestion:
        return False
    if len(suggestion) < 2:
        return False
    if suggestion.strip() == current_command.strip():
        return False
    if len(suggestion.split()) == 1 and len(suggestion) < 4:
        return False
    return True


def _fallback(command: str) -> str:
    """Rule-based fallback if model fails."""
    cmd = command.strip().lower().split()[0] if command.strip() else ""
    fallbacks = {
        "git"    : "git status",
        "cd"     : "ls -la",
        "ls"     : "cd ",
        "mkdir"  : "cd ",
        "python" : "pip install -r requirements.txt",
        "pip"    : "python script.py",
        "docker" : "docker ps -a",
        "make"   : "./output",
        "vim"    : "cat ",
        "cat"    : "grep '' ",
        "sudo"   : "sudo systemctl status",
    }
    return fallbacks.get(cmd, "ls -la")


# ── Test ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        ["git add ."],
        ["git add .", "git commit -m 'update'"],
        ["sudo apt update"],
        ["cd project", "ls -la"],
        ["python train.py"],
        ["docker build -t myapp ."],
    ]

    print("=" * 55)
    print("GPT-2 Next Command Prediction Test")
    print("=" * 55)

    for sequence in tests:
        reset_history()
        for cmd in sequence[:-1]:
            predict_next(cmd)
        suggestion = predict_next(sequence[-1])
        context    = " → ".join(sequence)
        print(f"Input  : {context}")
        print(f"Suggest: {suggestion}")
        print()