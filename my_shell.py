# my_shell.py

import os
import sys
import subprocess
import shlex
import time
from typing import List, Optional, Tuple, Dict

# ── Import AI modules ──────────────────────────────────────────────────────────
try:
    from risk_model import predict_risk
    from suggest_model import predict_next
except ImportError:
    print("Error: Could not import risk_model or suggest_model. Make sure they are available.")
    sys.exit(1)

# ── ANSI color support  ──────────────────────────────────────
try:
    import colorama
    colorama.init()
    ANSI_SUPPORT = True
except ImportError:
    ANSI_SUPPORT = False
    # If colorama not installed, fall back to raw ANSI (may not work on Windows)
    pass

class Colors:
    if ANSI_SUPPORT or os.name != "nt":
        RED    = "\033[91m"
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        BLUE   = "\033[94m"
        CYAN   = "\033[96m"
        BOLD   = "\033[1m"
        RESET  = "\033[0m"
    else:
        # No colors if ANSI unsupported and not on Windows (rare)
        RED = GREEN = YELLOW = BLUE = CYAN = BOLD = RESET = ""

# ── Persistent user data ───────────────────────────────────────────────────────
ALIAS_FILE = os.path.expanduser("~/.ai_shell_aliases")
LOG_FILE   = os.path.expanduser("~/.ai_shell_log")

def load_aliases() -> Dict[str, str]:
    aliases = {}
    if os.path.exists(ALIAS_FILE):
        with open(ALIAS_FILE, "r") as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    name, cmd = line.strip().split("=", 1)
                    aliases[name] = cmd
    return aliases

def save_aliases(aliases: Dict[str, str]) -> None:
    with open(ALIAS_FILE, "w") as f:
        for name, cmd in aliases.items():
            f.write(f"{name}={cmd}\n")

def log_command(command: str, verdict: str, confidence: float, executed: bool) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} | {verdict} | {confidence:.3f} | executed:{executed} | {command}\n")

# ── Built‑in commands ──────────────────────────────────────────────────────────
_global_safety_level = "normal"
_dir_stack = []
_last_dir = None

def builtin_cd(args: List[str]) -> bool:
    global _last_dir
    if not args:
        target = os.path.expanduser("~")
    else:
        target = args[0]
        if target == "-":
            if _last_dir is None:
                print(f"{Colors.YELLOW}cd: no previous directory{Colors.RESET}")
                return False
            target = _last_dir
        else:
            target = os.path.expanduser(target)
    try:
        orig = os.getcwd()
        os.chdir(target)
        _last_dir = orig
        return True
    except FileNotFoundError:
        print(f"{Colors.RED}cd: {target}: No such file or directory{Colors.RESET}")
    except PermissionError:
        print(f"{Colors.RED}cd: {target}: Permission denied{Colors.RESET}")
    except NotADirectoryError:
        print(f"{Colors.RED}cd: {target}: Not a directory{Colors.RESET}")
    return False

def builtin_pwd() -> None:
    print(os.getcwd())

def builtin_ls(args: List[str]) -> None:
    """List directory contents, ignoring options like -la."""
    # Filter out arguments that start with '-'
    paths = [arg for arg in args if not arg.startswith("-")]
    if not paths:
        paths = ["."]
    for path in paths:
        try:
            items = os.listdir(path)
            for item in sorted(items):
                print(item)
        except Exception as e:
            print(f"{Colors.RED}ls: {e}{Colors.RESET}")

def builtin_pushd(args: List[str]) -> None:
    global _dir_stack
    if not args:
        print(f"{Colors.YELLOW}pushd: missing directory{Colors.RESET}")
        return
    target = args[0]
    try:
        _dir_stack.append(os.getcwd())
        os.chdir(target)
        print(os.getcwd())
    except Exception as e:
        print(f"{Colors.RED}pushd: {e}{Colors.RESET}")

def builtin_popd(args: List[str]) -> None:
    global _dir_stack
    if not _dir_stack:
        print(f"{Colors.YELLOW}popd: directory stack empty{Colors.RESET}")
        return
    target = _dir_stack.pop()
    os.chdir(target)
    print(os.getcwd())

def builtin_dirs() -> None:
    print(" ".join(_dir_stack))

def builtin_safety(args: List[str]) -> None:
    global _global_safety_level
    if not args:
        print(f"Current safety level: {_global_safety_level}")
        print("Available levels: strict, normal, relaxed")
        return
    level = args[0].lower()
    if level in ("strict", "normal", "relaxed"):
        _global_safety_level = level
        print(f"Safety level set to {level}")
    else:
        print(f"{Colors.RED}Invalid safety level. Choose strict, normal, relaxed.{Colors.RESET}")

def builtin_alias(args: List[str], aliases: Dict[str, str]) -> None:
    if not args:
        for name, cmd in aliases.items():
            print(f"{name}='{cmd}'")
        return
    if "=" in args[0]:
        name, cmd = args[0].split("=", 1)
        aliases[name] = cmd
        save_aliases(aliases)
        print(f"Alias added: {name}='{cmd}'")
    else:
        name = args[0]
        if name in aliases:
            print(f"{name}='{aliases[name]}'")
        else:
            print(f"{Colors.YELLOW}Alias not found: {name}{Colors.RESET}")

def builtin_unalias(args: List[str], aliases: Dict[str, str]) -> None:
    if not args:
        print("Usage: unalias <name>")
        return
    name = args[0]
    if name in aliases:
        del aliases[name]
        save_aliases(aliases)
        print(f"Alias removed: {name}")
    else:
        print(f"{Colors.YELLOW}Alias not found: {name}{Colors.RESET}")

def builtin_history() -> None:
    if not os.path.exists(LOG_FILE):
        print("No log file found.")
        return
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-20:]
    for line in lines:
        print(line.rstrip())

def builtin_exit() -> None:
    print(f"\n{Colors.CYAN}Goodbye! Stay safe 🛡️{Colors.RESET}\n")
    sys.exit(0)

def builtin_help() -> None:
    print(f"""
{Colors.BOLD}AI‑Powered Command Assistant – Help{Colors.RESET}

{Colors.BOLD}Safety levels:{Colors.RESET}
  strict   → block all malicious commands (no confirmation)
  normal   → ask confirmation for malicious commands (default)
  relaxed  → only warn, never block

{Colors.BOLD}Built‑in commands:{Colors.RESET}
  exit, quit    → leave the shell
  help          → show this message
  cd [dir]      → change directory (supports ~, -, ..)
  pwd           → print working directory
  ls [path]     → list directory contents (ignores options like -la)
  pushd <dir>   → change directory and push old onto stack
  popd          → go back to last directory on stack
  dirs          → show directory stack
  safety [lvl]  → show or set safety level
  alias [name[=cmd]]   → show or create alias
  unalias <name>       → remove alias
  history       → show recent command log
  clear         → clear screen
  !!            → repeat last command

{Colors.BOLD}Keyboard shortcuts:{Colors.RESET}
  Up/Down   → browse command history
  Tab       → auto‑complete commands (if prompt_toolkit installed)
  Ctrl+R    → reverse search history (if prompt_toolkit installed)
  Ctrl+C    → cancel current line
  Ctrl+D    → exit
""")

# ── Command execution (without shell=True) ──────────────────────────────
def run_command(command_line: str, current_dir: str) -> Tuple[str, Optional[str]]:
    if not command_line.strip():
        return current_dir, None

    try:
        parts = shlex.split(command_line)
    except ValueError as e:
        print(f"{Colors.RED}Invalid syntax: {e}{Colors.RESET}")
        return current_dir, None

    if not parts:
        return current_dir, None

    cmd = parts[0]
    args = parts[1:]

    # Built‑ins
    if cmd == "cd":
        builtin_cd(args)
        return os.getcwd(), None
    elif cmd in ("exit", "quit"):
        builtin_exit()
    elif cmd == "help":
        builtin_help()
        return current_dir, None
    elif cmd == "pwd":
        builtin_pwd()
        return current_dir, None
    elif cmd == "ls":
        builtin_ls(args)
        return current_dir, None
    elif cmd == "pushd":
        builtin_pushd(args)
        return os.getcwd(), None
    elif cmd == "popd":
        builtin_popd(args)
        return os.getcwd(), None
    elif cmd == "dirs":
        builtin_dirs()
        return current_dir, None
    elif cmd == "safety":
        builtin_safety(args)
        return current_dir, None
    elif cmd == "alias":
        builtin_alias(args, aliases)
        return current_dir, None
    elif cmd == "unalias":
        builtin_unalias(args, aliases)
        return current_dir, None
    elif cmd == "history":
        builtin_history()
        return current_dir, None
    elif cmd == "clear":
        os.system("cls" if os.name == "nt" else "clear")
        return current_dir, None
    elif cmd == "!!":
        print(f"{Colors.YELLOW}No previous command.{Colors.RESET}")
        return current_dir, None

    # External command
    try:
        result = subprocess.run(parts, cwd=current_dir, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    except FileNotFoundError:
        print(f"{Colors.RED}Command not found: {cmd}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")

    return current_dir, None

# ── Rule‑based suggestion fallback ─────────────────────────────────────
def suggest_next_rule_based(last_command: str) -> Optional[str]:
    if last_command.startswith("cd"):
        return "ls -la"
    if last_command.startswith("ls"):
        return "pwd"
    if last_command.startswith("mkdir"):
        parts = last_command.split()
        new_dir = parts[1] if len(parts) > 1 else "newdir"
        return f"cd {new_dir}"
    if last_command.startswith("git clone"):
        return "cd"
    if last_command.startswith("git commit"):
        return "git push"
    if last_command.startswith("git push"):
        return "git status"
    if last_command.startswith(("vim", "nano")):
        return "cat"
    if last_command.startswith("make"):
        return "./program"
    return None

# ── Main loop with optional prompt_toolkit ─────────────────────────────
def main():
    global aliases, _global_safety_level

    aliases = load_aliases()

    # Try prompt_toolkit for better history/completion
    use_prompt_toolkit = False
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.styles import Style
        use_prompt_toolkit = True
    except ImportError:
        pass

    if use_prompt_toolkit:
        history_file = os.path.expanduser("~/.ai_shell_history")
        session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
            style=Style.from_dict({'prompt': 'ansicyan bold', 'path': 'ansiblue', 'dollar': 'ansigreen'})
        )
        completions = ["cd", "ls", "pwd", "exit", "help", "alias", "unalias", "history", "safety", "clear", "!!", "pushd", "popd", "dirs"] + list(aliases.keys())
        completer = WordCompleter(completions, ignore_case=True)
    else:
        session = None
        print(f"{Colors.YELLOW}For a better experience, install prompt_toolkit: pip install prompt_toolkit{Colors.RESET}")

    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║            AI Safe Command Line Assistant                 ║
║     DistilBERT + Rules + next command recommendations     ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
Type {Colors.GREEN}'help'{Colors.RESET} for usage. Safety level: {_global_safety_level}
""")

    current_dir = os.getcwd()
    last_command = ""

    while True:
        try:
            prompt = f"{Colors.CYAN}ai-shell{Colors.RESET} {Colors.BLUE}{current_dir}{Colors.RESET} $ "
            if use_prompt_toolkit:
                command = session.prompt(prompt, completer=completer).strip()
            else:
                command = input(prompt).strip()

            if not command:
                continue

            if command == "!!":
                if last_command:
                    command = last_command
                    print(f"{Colors.CYAN}Repeating: {command}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}No previous command.{Colors.RESET}")
                    continue

            # Expand alias
            parts = shlex.split(command)
            if parts and parts[0] in aliases:
                alias_cmd = aliases[parts[0]]
                command = alias_cmd + (" " + " ".join(shlex.quote(p) for p in parts[1:]) if len(parts) > 1 else "")
                print(f"{Colors.CYAN}(alias expanded: {command}){Colors.RESET}")

            # Risk detection
            label, confidence, reason = predict_risk(command)
            log_command(command, label, confidence, executed=False)

            block = False
            if label == "MALICIOUS":
                if _global_safety_level == "strict":
                    print(f"{Colors.RED}🔴 BLOCKED (strict mode): {reason}{Colors.RESET}")
                    block = True
                elif _global_safety_level == "normal":
                    print(f"{Colors.RED}🔴 DANGEROUS: {reason}{Colors.RESET}")
                    ans = input(f"{Colors.YELLOW}Run anyway? (yes/no): {Colors.RESET}").strip().lower()
                    if ans != "yes":
                        block = True
                    else:
                        print(f"{Colors.YELLOW}Running at your own risk...{Colors.RESET}")
                else:  # relaxed
                    print(f"{Colors.YELLOW}⚠️  MALICIOUS (relaxed mode): {reason}{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}✅ SAFE{Colors.RESET} ({confidence:.0%} confidence) — {reason}")

            if block:
                print(f"{Colors.GREEN}Command blocked.{Colors.RESET}\n")
                continue

            # Execute
            new_dir, _ = run_command(command, current_dir)
            if new_dir != current_dir:
                current_dir = new_dir

            log_command(command, label, confidence, executed=True)
            last_command = command

            # Generate suggestion
            suggestion = None
            try:
                suggestion = predict_next(command)
            except Exception:
                pass
            if not suggestion or suggestion == last_command:
                suggestion = suggest_next_rule_based(command)
            if suggestion:
                print(f"\n{Colors.CYAN}💡 Suggested next: {Colors.BOLD}{suggestion}{Colors.RESET}")

            print()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}(Use 'exit' or Ctrl+D to quit){Colors.RESET}")
            continue
        except EOFError:
            print()
            builtin_exit()

if __name__ == "__main__":
    main()