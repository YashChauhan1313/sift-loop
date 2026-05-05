#!/usr/bin/env python3
import os, re, shlex, subprocess, argparse
from datetime import datetime, timezone
from groq import Groq

# --- Configuration & Safety ---
MODEL = "llama-3.3-70b-versatile"
# Block obvious mutators and shell tricks
DENY = {"rm", "mv", "cp", "dd", "chmod", "chown", "mkdir", "apt", "pip", "curl", "wget", "sudo"}
ALLOW = {
    "ls", "stat", "file", "cat", "grep", "strings", "hexdump", "md5sum", "sha256sum",
    "exiftool", "vol", "volatility", "log2timeline", "ps", "df", "du", "whoami"
}

class SecurityError(Exception): pass

def is_safe(cmd):
    """Check if command is read-only and lacks shell injections."""
    cmd = cmd.strip()
    if not cmd or re.search(r"[;&`$(){}<>|]", cmd):
        return False, "Shell metacharacters detected"
    
    try:
        args = shlex.split(cmd)
        exe = os.path.basename(args[0]).lower()
    except:
        return False, "Parse error"

    if exe in DENY: return False, f"Blocked: {exe}"
    if exe not in ALLOW: return False, f"Not in allowlist: {exe}"
    
    # Block specific dangerous flags
    if exe == "sed" and any("-i" in a for a in args): return False, "In-place edit blocked"
    if exe == "find" and any(x in cmd for x in ["-exec", "-delete"]): return False, "find mutation blocked"
    
    return True, "OK"

# --- UI Helpers ---
def log(msg, color="0"):
    if os.isatty(1) and not os.getenv("NO_COLOR"):
        print(f"\033[{color}m{msg}\033[0m")
    else:
        print(msg)

# --- Core Logic ---
def run_cmd(cmd):
    safe, reason = is_safe(cmd)
    if not safe:
        raise SecurityError(f"{reason} -> {cmd}")
    
    proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=120)
    return proc.returncode, proc.stdout, proc.stderr

def ask_llm(cmd, code, out, err):
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    prompt = (
        "You are a forensics AI. Analyze this output. "
        "IMPORTANT: If the command failed, return ONLY the corrected terminal command "
        "on a single line with NO introductory text or explanations. "
        "If it worked, summarize findings briefly."
    )
    user_data = f"Cmd: {cmd}\nExit: {code}\nSTDOUT: {out}\nSTDERR: {err}"
    
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": prompt}, {"role": "user", "content": user_data}],
        temperature=0
    )
    return resp.choices[0].message.content.strip()

def write_report(orig, fixed, summary):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    with open("report.txt", "a") as f:
        f.write(f"{'='*40}\nUTC: {ts}\nCMD: {orig}\nFIX: {fixed or 'N/A'}\nSUMMARY: {summary}\n")

def triage(cmd, max_tries=3):
    orig_cmd = cmd
    current_cmd = cmd
    last_fix = None

    for i in range(1, max_tries + 1):
        log(f"[Attempt {i}/{max_tries}] Running: {current_cmd}", "1;36")
        
        code, out, err = run_cmd(current_cmd)
        res = ask_llm(current_cmd, code, out, err)
        
# Check if LLM gave a single-line command to retry
        lines = res.splitlines()
        # Add a check: real commands don't usually have 5+ words
        if len(lines) == 1 and len(res.split()) < 5 and is_safe(res)[0]:
            log(f"(!) Attempt {i} failed. AI suggesting fix: {res}", "33")
            current_cmd = res
            last_fix = res
            continue
        
        # Success or Final response
        write_report(orig_cmd, last_fix, res)
        return res
    return "Max retries reached without clear success."

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", nargs="+")
    parser.add_argument("--tries", type=int, default=3)
    args = parser.parse_args()

    if not os.getenv("GROQ_API_KEY"):
        raise SystemExit("Error: Set GROQ_API_KEY env var.")

    full_cmd = " ".join(args.cmd)
    try:
        print(triage(full_cmd, args.tries))
    except Exception as e:
        log(f"FAILED: {e}", "31")
