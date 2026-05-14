#!/usr/bin/env python3
# my_shell.py — AI Safe Command Line Assistant
# Beautiful UI with fixed Windows colors + all improvements

import os
import sys
import subprocess
import shlex
import time
from typing import List, Optional, Dict

# ── Fix Windows ANSI colors - SIMPLE VERSION ───────────────────────────────────
if sys.platform == "win32":
    import ctypes
    kernel32 = ctypes.windll.kernel32
    # Enable virtual terminal processing
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    hOut = kernel32.GetStdHandle(-11)
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
        kernel32.SetConsoleMode(hOut, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)

os.system("")

# DO NOT import colorama - it causes issues with prompt_toolkit

# ── Import AI modules ──────────────────────────────────────────────────────────
try:
    from risk_model import predict_risk, get_category, explain_prediction
    from suggest_model import predict_next
except ImportError as e:
    print(f"Error: Could not import AI modules: {e}")
    sys.exit(1)

# ── Colors ─────────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": C.RED,
    "HIGH"    : C.YELLOW,
    "MEDIUM"  : C.MAGENTA,
    "LOW"     : C.CYAN,
}

# ── Terminal-friendly icons ────────────────────────────────────────
class I:
    # Safety & Status
    SHIELD      = "🛡️"
    CHECK       = "✓"
    CROSS       = "✗"
    WARNING     = "⚠"
    INFO        = "ℹ"
    QUESTION    = "?"
    BLOCKED     = "⛔"
    
    # Threat levels
    CRITICAL    = "💀"
    HIGH        = "▲"
    MEDIUM      = "●"
    LOW         = "○"
    
    # Commands & Navigation
    ARROW       = "→"
    PROMPT      = "❯"
    DOT         = "●"
    FOLDER      = "📁"
    FILE        = "📄"
    BACK        = "↺"
    
    # Time & Stats
    CLOCK       = "⏱"
    LIST        = "📋"
    LOCK        = "🔒"
    UNLOCK      = "🔓"
    TARGET      = "🎯"
    
    # AI & Detection
    BRAIN       = "🧠"
    ROBOT       = "🤖"
    MAGIC       = "✨"
    LIGHTBULB   = "💡"
    
    # Security
    FIREWALL    = "🔥"
    SKULL       = "💀"
    BUG         = "🐛"
    
    # Arrows & Lines
    LINE        = "─"
    BAR         = "█"
    DOT_SMALL   = "▪"

# ── Session Statistics ─────────────────────────────────────────────────────────
class SessionStats:
    def __init__(self):
        self.total      = 0
        self.safe       = 0
        self.malicious  = 0
        self.suspicious = 0
        self.uncertain  = 0
        self.blocked    = 0
        self.overridden = 0
        self.categories : Dict[str, int] = {}
        self.start_time = time.time()

    def update(self, label: str, category: str = None,
               blocked: bool = False, overridden: bool = False):
        self.total += 1
        if   label == "SAFE"      : self.safe       += 1
        elif label == "MALICIOUS" : self.malicious   += 1
        elif label == "SUSPICIOUS": self.suspicious  += 1
        elif label == "UNCERTAIN" : self.uncertain   += 1
        if blocked   : self.blocked    += 1
        if overridden: self.overridden += 1
        if category and label in ("MALICIOUS", "SUSPICIOUS"):
            self.categories[category] = self.categories.get(category, 0) + 1

    def print_summary(self):
        elapsed    = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        safety_pct = (self.safe / self.total * 100) if self.total else 100
        bar_filled = int(safety_pct / 5)
        bar        = I.BAR * bar_filled + "░" * (20 - bar_filled)
        bar_color  = C.GREEN if safety_pct >= 80 else (C.YELLOW if safety_pct >= 50 else C.RED)

        W = 48  # inner width

        def pad(text, width=W):
            return text + " " * max(0, width - len(text))

        print(f"\n{C.CYAN}{C.BOLD}")
        print(f"  ╔{'═' * W}╗")
        print(f"  ║{pad(''):^{W}}║")
        print(f"  ║{pad(f'  {I.SHIELD}  SESSION SECURITY SUMMARY', W)}║")
        print(f"  ║{pad(''):^{W}}║")
        print(f"  ╠{'═' * W}╣")

        rows = [
            (f"  {I.CLOCK}  Duration      : {mins}m {secs}s",          C.WHITE),
            (f"  {I.LIST}  Total commands : {self.total}",             C.WHITE),
            (f"  {I.CHECK}  Safe           : {self.safe}",              C.GREEN),
            (f"  {I.BLOCKED}  Blocked        : {self.blocked}",           C.RED),
            (f"  {I.WARNING}  Suspicious    : {self.suspicious}",        C.YELLOW),
            (f"  {I.QUESTION}  Uncertain      : {self.uncertain}",         C.MAGENTA),
            (f"  {I.UNLOCK}  Overridden     : {self.overridden}",        C.YELLOW),
        ]
        for text, color in rows:
            spaces = W - len(text)
            print(f"  ║{color}{text}{C.CYAN}{' ' * max(0, spaces)}║")

        if self.categories:
            print(f"  ╠{'═' * W}╣")
            print(f"  ║{C.BOLD}  {I.TARGET} THREATS DETECTED:{C.CYAN}{' ' * (W - 22)}║")
            for cat, count in sorted(self.categories.items(),
                                     key=lambda x: x[1], reverse=True):
                cat_title = cat.replace("_", " ").title()
                bar_t     = I.DOT_SMALL * min(count * 3, 12)
                line      = f"  {cat_title:<22} {bar_t} {count}"
                spaces    = W - len(line)
                print(f"  ║{C.RED}{line}{C.CYAN}{' ' * max(0, spaces)}║")

        print(f"  ╠{'═' * W}╣")
        score_raw    = f"  Safety Score : [{bar}] {safety_pct:.0f}%"
        score_colored= f"  Safety Score : [{bar_color}{bar}{C.CYAN}] {safety_pct:.0f}%"
        spaces       = W - len(score_raw)
        print(f"  ║{score_colored}{' ' * max(0, spaces)}║")
        print(f"  ╚{'═' * W}╝{C.RESET}\n")


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

def log_command(command: str, verdict: str, confidence: float,
                category: str, executed: bool) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts} | {verdict:<10} | {confidence:.3f}"
                f" | {category:<25} | executed:{executed} | {command}\n")


# ── Global state ───────────────────────────────────────────────────────────────
_global_safety_level = "normal"
_dir_stack           = []
_last_dir            = None
DEBUG                = False


# ── Built-in commands ──────────────────────────────────────────────────────────
def builtin_cd(args):
    global _last_dir
    target = os.path.expanduser("~") if not args else args[0]
    if target == "-":
        if _last_dir is None:
            print(f"  {C.YELLOW}cd: no previous directory{C.RESET}")
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
        print(f"  {C.RED}cd: {target}: No such file or directory{C.RESET}")
    except PermissionError:
        print(f"  {C.RED}cd: {target}: Permission denied{C.RESET}")
    except NotADirectoryError:
        print(f"  {C.RED}cd: {target}: Not a directory{C.RESET}")
    return False


def builtin_ls(args):
    paths = [a for a in args if not a.startswith("-")] or ["."]
    for path in paths:
        try:
            items = sorted(os.listdir(path))
            dirs  = [i for i in items if os.path.isdir(os.path.join(path, i))]
            files = [i for i in items if not os.path.isdir(os.path.join(path, i))]
            for d in dirs:
                print(f"  {C.CYAN}{C.BOLD}{I.FOLDER} {d}/{C.RESET}")
            for f in files:
                print(f"  {I.FILE} {f}")
        except Exception as e:
            print(f"  {C.RED}ls: {e}{C.RESET}")


def builtin_safety(args):
    global _global_safety_level
    colors = {"strict": C.RED, "normal": C.YELLOW, "relaxed": C.GREEN}
    if not args:
        col = colors.get(_global_safety_level, C.WHITE)
        print(f"  Safety level: {col}{C.BOLD}{_global_safety_level}{C.RESET}")
        print(f"  Options: {C.RED}strict{C.RESET} | {C.YELLOW}normal{C.RESET} | {C.GREEN}relaxed{C.RESET}")
        return
    level = args[0].lower()
    if level in ("strict", "normal", "relaxed"):
        _global_safety_level = level
        col = colors[level]
        print(f"  {C.GREEN}{I.CHECK} Safety level → {col}{C.BOLD}{level}{C.RESET}")
    else:
        print(f"  {C.RED}{I.CROSS} Invalid. Choose: strict | normal | relaxed{C.RESET}")


def builtin_alias(args, aliases):
    if not args:
        if not aliases:
            print(f"  {C.DIM}No aliases defined.{C.RESET}")
            return
        for name, cmd in aliases.items():
            print(f"  {C.CYAN}{name}{C.RESET} = '{cmd}'")
        return
    if "=" in args[0]:
        name, cmd = args[0].split("=", 1)
        aliases[name] = cmd
        save_aliases(aliases)
        print(f"  {C.GREEN}{I.CHECK} Alias: {C.CYAN}{name}{C.RESET} = '{cmd}'")
    else:
        name = args[0]
        if name in aliases:
            print(f"  {C.CYAN}{name}{C.RESET} = '{aliases[name]}'")
        else:
            print(f"  {C.YELLOW}{I.WARNING} Alias not found: {name}{C.RESET}")


def builtin_history():
    if not os.path.exists(LOG_FILE):
        print(f"  {C.DIM}No log file found.{C.RESET}")
        return
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-20:]
    print(f"\n  {C.BOLD}{'Timestamp':<21}{'Verdict':<12}{'Conf':<7}{'Category':<26}Command{C.RESET}")
    print(f"  {I.LINE * 85}")
    for line in lines:
        parts = line.strip().split(" | ")
        if len(parts) >= 5:
            ts, verdict, conf, cat, rest = (parts[0], parts[1], parts[2],
                                             parts[3], " | ".join(parts[4:]))
            cmd = rest.replace("executed:True | ", "").replace("executed:False | ", "")
            col = C.GREEN if "SAFE" in verdict else C.RED
            print(f"  {C.DIM}{ts}{C.RESET}  {col}{verdict.strip():<12}{C.RESET}"
                  f"{conf.strip():<7} {C.DIM}{cat.strip():<26}{C.RESET}{cmd[:40]}")
    print()


def builtin_exit(stats):
    stats.print_summary()
    print(f"  {C.CYAN}{C.BOLD}{I.SHIELD}  Goodbye! Stay safe {I.SHIELD}{C.RESET}\n")
    sys.exit(0)


def builtin_help():
    print(f"""
{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════╗
  ║          AI Shell — Help & Commands              ║
  ╚══════════════════════════════════════════════════╝{C.RESET}

  {C.BOLD}How it works:{C.RESET}
    {C.YELLOW}①{C.RESET} {C.BOLD}Rules layer{C.RESET}  → instant detection of known attack patterns
    {C.YELLOW}②{C.RESET} {C.BOLD}DistilBERT{C.RESET}   → AI classifier (100k labeled commands)
    {C.YELLOW}③{C.RESET} {C.BOLD}GPT-2{C.RESET}        → predicts your next command from history

  {C.BOLD}Risk levels:{C.RESET}
    {C.RED}{I.CRITICAL} CRITICAL{C.RESET}  — system destruction, root access, reverse shells
    {C.YELLOW}{I.HIGH} HIGH{C.RESET}      — data theft, persistence, log wiping
    {C.MAGENTA}{I.MEDIUM} MEDIUM{C.RESET}    — network scanning, crypto mining
    {C.GREEN}{I.CHECK} SAFE{C.RESET}      — normal command

  {C.BOLD}Safety modes:{C.RESET}
    {C.RED}strict{C.RESET}   → block all threats instantly, no confirmation
    {C.YELLOW}normal{C.RESET}   → ask confirmation before blocking (default)
    {C.GREEN}relaxed{C.RESET}  → warn only, never block

  {C.BOLD}Commands:{C.RESET}
    {C.CYAN}exit / quit{C.RESET}     → leave (shows session summary)
    {C.CYAN}help{C.RESET}            → this message
    {C.CYAN}stats{C.RESET}           → live session statistics
    {C.CYAN}safety [lvl]{C.RESET}    → show or set safety level
    {C.CYAN}history{C.RESET}         → command audit log
    {C.CYAN}debug{C.RESET}           → toggle GPT-2 debug info
    {C.CYAN}cd / ls / pwd{C.RESET}   → navigation (built-in, works on Windows)
    {C.CYAN}alias / unalias{C.RESET} → manage aliases
    {C.CYAN}pushd/popd/dirs{C.RESET} → directory stack
    {C.CYAN}!{C.RESET}{C.CYAN}!{C.RESET}              → repeat last command
    {C.CYAN}clear{C.RESET}           → clear screen
""")


# ── Rule-based suggestion fallback ────────────────────────────────────────────
def suggest_rule_based(command: str) -> Optional[str]:
    c = command.strip().lower()
    
    # ── SMART HELP SUGGESTIONS (Priority) ─────────────────────────────────────
    if c == "help":
        return "stats  (see your session security summary)"
    
    if c == "help stats":
        return "stats"
    
    if c == "help safety":
        return "safety normal"
    
    if c == "help history":
        return "history"
    
    if c == "help alias":
        return "alias"
    
    if c == "help debug":
        return "debug"
    
    if c.startswith("help "):
        topic = c.split()[1] if len(c.split()) > 1 else ""
        topic_map = {
            "stats": "stats",
            "safety": "safety",
            "history": "history",
            "alias": "alias",
            "debug": "debug",
            "exit": "stats then exit",
            "commands": "ls",
            "navigation": "cd ..",
        }
        if topic in topic_map:
            return f"{topic_map[topic]}  (try this after learning about {topic})"
        return "stats  (view your session statistics)"
    
    # ── DOCKER COMMANDS SUGGESTIONS ──────────────────────────────────────────
    if c.startswith("docker --version") or c.startswith("docker version"):
        return "docker info"
    
    if c.startswith("docker info"):
        return "docker ps"
    
    if c.startswith("docker pull"):
        return "docker images"
    
    if c.startswith("docker images"):
        return "docker run -it "
    
    if c.startswith("docker run"):
        return "docker ps"
    
    if c.startswith("docker ps"):
        if "-a" in c:
            return "docker rm "
        return "docker ps -a"
    
    if c.startswith("docker stop"):
        return "docker rm"
    
    if c.startswith("docker rm"):
        return "docker ps -a"
    
    if c.startswith("docker logs"):
        return "docker ps"
    
    if c.startswith("docker exec"):
        return "docker ps"
    
    if c.startswith("docker build"):
        return "docker images"
    
    if c.startswith("docker-compose up"):
        return "docker-compose ps"
    
    if c.startswith("docker-compose down"):
        return "docker-compose ps"
    
    if c.startswith("docker-compose ps"):
        return "docker-compose logs"
    
    # ── GIT COMMANDS SUGGESTIONS ─────────────────────────────────────────────
    if c.startswith("git init"):
        return "git add ."
    
    if c.startswith("git add"):
        return "git commit -m 'initial commit'"
    
    if c.startswith("git commit"):
        return "git push origin main"
    
    if c.startswith("git push"):
        return "git status"
    
    if c.startswith("git status"):
        return "git log --oneline"
    
    if c.startswith("git log"):
        return "git diff"
    
    if c.startswith("git clone"):
        return "cd "
    
    # ── NAVIGATION & USEFUL SUGGESTIONS ──────────────────────────────────────
    if c == "stats":
        return "help  (see all available commands)"
    
    if c == "safety":
        return "safety strict  (for maximum protection)"
    
    if c == "history":
        return "!!  (repeat last command)"
    
    if c == "debug":
        return "stats  (see AI performance)"
    
    if c == "ls":
        return "cd ..  (go to parent directory)"
    
    if c == "pwd":
        return "ls -la  (list all files)"
    
    if c == "cd" or c == "cd ~":
        return "ls -la"
    
    if c.startswith("cd "):
        return "ls"
    
    if c.startswith("mkdir"):
        parts = command.split()
        return f"cd {parts[1]}" if len(parts) > 1 else "cd newdir"
    
    if c.startswith("sudo apt update"):
        return "sudo apt upgrade"
    
    if c.startswith("sudo apt upgrade"):
        return "sudo apt autoremove"
    
    if c.startswith("pip install"):
        return "pip list"
    
    if c.startswith("python"):
        return "pip freeze > requirements.txt"
    
    return None


# ── Command execution ──────────────────────────────────────────────────────────
def run_command(command_line: str, current_dir: str, stats) -> tuple[str, bool]:
    if not command_line.strip():
        return current_dir, False
    
    try:
        parts = shlex.split(command_line)
    except ValueError as e:
        print(f"  {C.RED}Syntax error: {e}{C.RESET}")
        return current_dir, True

    if not parts:
        return current_dir, False

    cmd  = parts[0]
    args = parts[1:]

    # Built-ins
    if   cmd == "cd"                   : builtin_cd(args);    return os.getcwd(), True
    elif cmd in ("exit", "quit")       : builtin_exit(stats)
    elif cmd == "help"                 : builtin_help();       return current_dir, True
    elif cmd == "pwd"                  : print(f"  {os.getcwd()}"); return current_dir, True
    elif cmd == "ls"                   : builtin_ls(args);     return current_dir, True
    elif cmd == "pushd"                :
        if args:
            try:
                _dir_stack.append(os.getcwd())
                os.chdir(args[0])
                print(f"  {os.getcwd()}")
            except Exception as e:
                print(f"  {C.RED}pushd: {e}{C.RESET}")
        return os.getcwd(), True
    elif cmd == "popd"                 :
        if _dir_stack:
            os.chdir(_dir_stack.pop())
            print(f"  {os.getcwd()}")
        else:
            print(f"  {C.YELLOW}popd: stack empty{C.RESET}")
        return os.getcwd(), True
    elif cmd == "dirs"                 :
        print(f"  {' '.join(_dir_stack) or '(empty)'}")
        return current_dir, True
    elif cmd == "safety"               : builtin_safety(args); return current_dir, True
    elif cmd == "alias"                : builtin_alias(args, aliases); return current_dir, True
    elif cmd == "unalias"              :
        if args and args[0] in aliases:
            del aliases[args[0]]
            save_aliases(aliases)
            print(f"  {C.GREEN}{I.CHECK} Alias removed: {args[0]}{C.RESET}")
        return current_dir, True
    elif cmd == "history"              : builtin_history();    return current_dir, True
    elif cmd == "clear"                :
        os.system("cls" if os.name == "nt" else "clear")
        return current_dir, True

    # External command
    try:
        result = subprocess.run(parts, cwd=current_dir,
                                capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.splitlines():
                print(f"  {line}")
        if result.stderr:
            for line in result.stderr.splitlines():
                print(f"  {C.DIM}{line}{C.RESET}", file=sys.stderr)
        return current_dir, result.returncode == 0
    except FileNotFoundError:
        print(f"  {C.RED}{I.CROSS} Command not found: {C.BOLD}{cmd}{C.RESET}")
        return current_dir, False
    except Exception as e:
        print(f"  {C.RED}Error: {e}{C.RESET}")
        return current_dir, False


# ── Risk display ───────────────────────────────────────────────────────────────
def print_risk_block(label, confidence, severity, category,
                     explanation, reason, command):
    sev_color = SEVERITY_COLOR.get(severity, C.RED)
    cat_title = category.replace("_", " ").title()

    if label == "MALICIOUS":
        icon, header, hcol = I.SKULL, "DANGEROUS COMMAND DETECTED", C.RED
    elif label == "SUSPICIOUS":
        icon, header, hcol = I.WARNING, "SUSPICIOUS COMMAND", C.YELLOW
    else:
        icon, header, hcol = I.QUESTION, "UNCERTAIN — PLEASE VERIFY", C.MAGENTA

    print()
    print(f"  {hcol}{C.BOLD}{icon}  {header}{C.RESET}")
    print(f"  {hcol}{I.LINE * 52}{C.RESET}")
    print(f"  {C.DIM}Confidence  {C.RESET}: {C.BOLD}{confidence:.0%}{C.RESET}")
    print(f"  {C.DIM}Severity    {C.RESET}: {sev_color}{C.BOLD}{severity}{C.RESET}")
    print(f"  {C.DIM}Category    {C.RESET}: {C.CYAN}{cat_title}{C.RESET}")
    print(f"  {C.DIM}Why         {C.RESET}: {explanation}")
    print(f"  {C.DIM}Detection   {C.RESET}: {reason}")

    # Attention tokens
    if "Model" in reason and label == "MALICIOUS":
        try:
            tokens = explain_prediction(command)
            if tokens:
                top = "  ".join(
                    [f"{C.YELLOW}'{t}'{C.RESET}{C.DIM}({s:.2f}){C.RESET}"
                     for t, s in tokens[:3]]
                )
                print(f"  {C.DIM}Key tokens  {C.RESET}: {top}")
        except Exception:
            pass

    print(f"  {hcol}{I.LINE * 52}{C.RESET}")


# ── Main loop ──────────────────────────────────────────────────────────────────
def main():
    global aliases, _global_safety_level, DEBUG, use_pt, session, completer

    # Re-enable ANSI support (sometimes gets reset)
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        hOut = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
            kernel32.SetConsoleMode(hOut, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)

    aliases = load_aliases()
    stats   = SessionStats()

    # ── Try prompt_toolkit ──────────────────────────────────────────────────────
    use_pt = False
    session = None
    completer = None
    
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.formatted_text import ANSI
        
        session = PromptSession(
            history=FileHistory(os.path.expanduser("~/.ai_shell_history")),
            auto_suggest=AutoSuggestFromHistory(),
        )
        
        completions = [
            "cd","ls","pwd","exit","quit","help","alias","unalias",
            "history","safety","clear","!!","pushd","popd","dirs",
            "debug","stats","safety strict","safety normal","safety relaxed"
        ] + list(aliases.keys())
        completer = WordCompleter(completions, ignore_case=True)
        use_pt = True
    except ImportError:
        session = None
        completer = None
        print(f"  {C.YELLOW}{I.WARNING}  prompt_toolkit not available, using basic input{C.RESET}")

    # ── Banner ─────────────────────────────────────────────────────────────────
    safety_cols = {"strict": C.RED, "normal": C.YELLOW, "relaxed": C.GREEN}
    scol        = safety_cols[_global_safety_level]

    print(f"""
{C.CYAN}{C.BOLD}
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║    {I.SHIELD}   AI Safe Command Line Assistant                   ║
  ║                                                          ║
  ║    {C.DIM}{I.BRAIN} DistilBERT  ·  {I.ROBOT} Rules Engine  ·  {I.MAGIC} GPT-2{C.RESET}{C.CYAN}{C.BOLD}            ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
{C.RESET}
  {C.DIM}Safety:{C.RESET} {scol}{C.BOLD}{_global_safety_level}{C.RESET}   {C.DIM}|{C.RESET}   {C.DIM}Type{C.RESET} {C.CYAN}help{C.RESET} {C.DIM}for commands{C.RESET}
""")

    current_dir  = os.getcwd()
    last_command = ""

    while True:
        try:
            # ── Prompt ─────────────────────────────────────────────────────
            scol_now = safety_cols.get(_global_safety_level, C.WHITE)
            dot      = f"{scol_now}{I.DOT}{C.RESET}"

            # Shorten path for display
            home = os.path.expanduser("~")
            disp = current_dir.replace(home, "~")
            if len(disp) > 45:
                p    = disp.replace("\\", "/").split("/")
                disp = "…/" + "/".join(p[-2:])

            prompt = (f"\n  {dot} {C.CYAN}{C.BOLD}ai-shell{C.RESET} "
                      f"{C.DIM}({disp}){C.RESET}\n  {C.DIM}{I.PROMPT}{C.RESET} ")

            # Get command input with proper ANSI support
            if use_pt and session:
                from prompt_toolkit.formatted_text import ANSI
                formatted_prompt = ANSI(prompt)
                command = session.prompt(formatted_prompt, completer=completer).strip()
            else:
                command = input(prompt).strip()

            if not command:
                continue

            # ── Special commands ────────────────────────────────────────────
            if command == "debug":
                DEBUG  = not DEBUG
                status = f"{C.YELLOW}ON {I.DOT}{C.RESET}" if DEBUG else f"{C.GREEN}OFF {I.DOT}{C.RESET}"
                print(f"  Debug mode: {status}")
                continue

            if command == "stats":
                stats.print_summary()
                continue

            # ── Repeat ─────────────────────────────────────────────────────
            if command == "!!":
                if last_command:
                    command = last_command
                    print(f"  {C.CYAN}{I.BACK}  {command}{C.RESET}")
                else:
                    print(f"  {C.YELLOW}{I.WARNING} No previous command.{C.RESET}")
                    continue

            # ── Alias expand ────────────────────────────────────────────────
            try:
                parts = shlex.split(command)
                if parts and parts[0] in aliases:
                    rest    = " ".join(shlex.quote(p) for p in parts[1:])
                    command = f"{aliases[parts[0]]} {rest}".strip()
                    print(f"  {C.DIM}{I.ARROW} alias: {command}{C.RESET}")
            except ValueError:
                pass

            # ── Task 1: Risk Detection ──────────────────────────────────────
            label, confidence, reason = predict_risk(command)

            category    = "safe"
            severity    = ""
            explanation = ""
            if label in ("MALICIOUS", "SUSPICIOUS", "UNCERTAIN"):
                category, severity, explanation = get_category(command)

            log_command(command, label, confidence, category, executed=False)

            block      = False
            overridden = False

            if label in ("MALICIOUS", "SUSPICIOUS", "UNCERTAIN"):
                print_risk_block(label, confidence, severity, category,
                                 explanation, reason, command)

                # Comportement selon le mode de sécurité
                if _global_safety_level == "strict":
                    # Strict mode: always block without asking
                    print(f"\n  {C.RED}{C.BOLD}{I.BLOCKED}  Blocked — strict mode active{C.RESET}")
                    block = True
                    
                elif _global_safety_level == "relaxed":
                    # Relaxed mode: warn only, never block
                    print(f"\n  {C.YELLOW}{I.WARNING}  Warning: {label} command detected{C.RESET}")
                    print(f"  {C.DIM}Running automatically (relaxed mode){C.RESET}")
                    block = False
                    overridden = False
                    
                else:  # normal mode
                    # Normal mode: ask for confirmation
                    try:
                        ans = input(
                            f"\n  {C.YELLOW}Run anyway?{C.RESET} {C.DIM}(yes/no){C.RESET} › "
                        ).strip().lower()
                    except KeyboardInterrupt:
                        print(f"\n  {C.GREEN}{I.CHECK} Cancelled.{C.RESET}")
                        stats.update(label, category, blocked=True)
                        continue

                    if ans != "yes":
                        block = True
                    else:
                        overridden = True
                        print(f"  {C.YELLOW}{I.LIGHTBULB} Running at your own risk...{C.RESET}")

            else:
                print(f"  {C.GREEN}{I.CHECK} SAFE{C.RESET}  "
                      f"{C.DIM}{confidence:.0%} confidence  ·  {reason}{C.RESET}")

            stats.update(label, category, blocked=block, overridden=overridden)

            if block:
                print(f"  {C.GREEN}{I.CHECK} Command blocked safely.{C.RESET}\n")
                continue

            # ── Execute ─────────────────────────────────────────────────────
            print()
            current_dir, success = run_command(command, current_dir, stats)
            log_command(command, label, confidence, category, executed=True)
            last_command = command

            # ── Task 2: GPT-2 Suggestion ────────────────────────────────────
            gpt2_raw = None
            try:
                gpt2_raw = predict_next(command)
            except Exception as e:
                if DEBUG:
                    print(f"  {C.DIM}[DEBUG] GPT-2 error: {e}{C.RESET}")

            if DEBUG:
                print(f"  {C.DIM}[DEBUG] GPT-2 raw : '{gpt2_raw}'{C.RESET}")
            
            # Disable GPT-2 for specific commands
            if command.strip().lower() in ["help", "help stats", "help safety", "help history"]:
                gpt2_raw = None
                if DEBUG:
                    print(f"  {C.DIM}[DEBUG] GPT-2 disabled for '{command}'{C.RESET}")
            
            if gpt2_raw and gpt2_raw != last_command and len(str(gpt2_raw)) > 2:
                suggestion = gpt2_raw
                source     = "GPT-2"
            else:
                suggestion = suggest_rule_based(command)
                source     = "rule"

            if DEBUG:
                print(f"  {C.DIM}[DEBUG] Source    : {source}{C.RESET}")

            if suggestion:
                src_tag = f" {C.DIM}[{source}]{C.RESET}" if DEBUG else ""
                print(f"\n  {C.CYAN}{I.LIGHTBULB}{C.RESET} {C.DIM}Next:{C.RESET} "
                      f"{C.BOLD}{suggestion}{C.RESET}{src_tag}")

        except KeyboardInterrupt:
            print(f"\n  {C.YELLOW}(Ctrl+D or type 'exit' to quit){C.RESET}")
            continue
        except EOFError:
            print()
            builtin_exit(stats)


if __name__ == "__main__":
    # Make aliases global for builtin functions
    aliases = {}
    session = None
    completer = None
    use_pt = False
    main()