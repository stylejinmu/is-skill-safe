"""
audit_skill.py - Static security analysis for AI agent Skills.

Scans a skill directory for potentially dangerous patterns in SKILL.md
and associated scripts (Python, Shell, JavaScript).

Usage:
    python audit_skill.py <path_to_skill_directory>
"""

import os
import sys
import re
from dataclasses import dataclass
from typing import List, Tuple


# ---------------------------------------------------------------------------
# DANGEROUS_PATTERNS
# ---------------------------------------------------------------------------
# Each entry is (regex_pattern, description, severity)
# severity: "HIGH" | "MEDIUM" | "LOW"

PYTHON_PATTERNS: List[Tuple[str, str, str]] = [
    # --- Code Execution Injection ---
    (r'\beval\s*\(',                    "eval() - executes arbitrary string as code",                                   "HIGH"),
    (r'\bexec\s*\(',                    "exec() - executes arbitrary Python code block",                                "HIGH"),
    (r'\bcompile\s*\(',                 "compile() - dynamically compiles code objects",                                "HIGH"),
    (r'\bexecfile\s*\(',                "execfile() - executes arbitrary file as code (Python 2)",                      "HIGH"),
    (r'\b__import__\s*\(',              "__import__() - dynamic import, can bypass static analysis",                    "HIGH"),
    (r'\blogging\.config\.listen\s*\(', "logging.config.listen() - receives config via socket and evals it (RCE risk)", "HIGH"),
    (r'\bcode\.InteractiveConsole\s*\(', "code.InteractiveConsole() - interactive Python interpreter, executes arbitrary code", "HIGH"),
    (r'\bcode\.InteractiveInterpreter\s*\(', "code.InteractiveInterpreter() - interactive Python interpreter, executes arbitrary code", "HIGH"),
    (r'\bglobals\s*\(\s*\)',            "globals() - accessing global symbol table dynamically can invoke arbitrary functions", "HIGH"),
    (r'\blocals\s*\(\s*\)',             "locals() - accessing local symbol table dynamically can invoke arbitrary functions", "MEDIUM"),

    # --- System Command Execution ---
    (r'\bos\.system\s*\(',             "os.system() - executes shell command, command injection risk",                 "HIGH"),
    (r'\bos\.popen\s*\(',              "os.popen() - opens shell pipe, command injection risk",                       "HIGH"),
    (r'\bos\.exec[lv]',                "os.exec*() - replaces current process with new program",                      "HIGH"),
    (r'\bos\.spawn',                   "os.spawn*() - spawns subprocess to execute command",                          "HIGH"),
    (r'\bsubprocess\.Popen\s*\(',      "subprocess.Popen() - starts subprocess (risky if shell=True)",                "HIGH"),
    (r'\bsubprocess\.run\s*\(',        "subprocess.run() - runs subprocess (risky if shell=True)",                    "HIGH"),
    (r'\bsubprocess\.call\s*\(',       "subprocess.call() - calls subprocess (risky if shell=True)",                  "HIGH"),
    (r'\bsubprocess\.check_output\s*\(', "subprocess.check_output() - captures subprocess output",                   "MEDIUM"),

    # --- Unsafe Deserialization ---
    (r'\bpickle\.loads?\s*\(',         "pickle.load/loads() - deserializing untrusted data can execute arbitrary code", "HIGH"),
    (r'\bmarshal\.loads?\s*\(',        "marshal.load/loads() - unsafe deserialization of binary data",                "HIGH"),
    (r'\byaml\.load\s*\(',             "yaml.load() - use yaml.safe_load() instead to avoid code execution",          "HIGH"),
    (r'\bshelve\.open\s*\(',           "shelve.open() - uses pickle internally, same deserialization risk",           "MEDIUM"),

    # --- Dangerous Imports ---
    (r'\bimport\s+telnetlib\b',        "import telnetlib - Telnet is insecure (plaintext), use SSH instead",          "HIGH"),
    (r'\bimport\s+ftplib\b',           "import ftplib - FTP transmits credentials in plaintext, use SFTP/SCP",        "HIGH"),
    (r'\bimport\s+ctypes\b',           "import ctypes - direct access to low-level OS/Windows APIs, common in malware", "HIGH"),
    (r'\bimport\s+xmlrpc\b',           "import xmlrpc - XMLRPC is vulnerable to XML injection attacks",               "HIGH"),
    (r'\bfrom\s+Crypto\b',             "from Crypto - pycrypto is deprecated with known buffer overflow vulnerability", "HIGH"),
    (r'\bimport\s+dill\b',             "import dill - extends pickle, deserializing untrusted data can execute arbitrary code", "MEDIUM"),

    # --- Unsafe XML Parsing ---
    (r'xml\.etree\.(c?ElementTree|cElementTree)', "xml.etree - vulnerable to XML Bomb/XXE attacks, use defusedxml instead", "MEDIUM"),
    (r'xml\.sax\.',                    "xml.sax - vulnerable to XML Bomb/XXE attacks, use defusedxml instead",        "MEDIUM"),
    (r'xml\.dom\.minidom',             "xml.dom.minidom - vulnerable to XML Bomb/XXE attacks, use defusedxml instead", "MEDIUM"),
    (r'xml\.dom\.pulldom',             "xml.dom.pulldom - vulnerable to XML Bomb/XXE attacks, use defusedxml instead", "MEDIUM"),
    (r'lxml\.etree\.(parse|fromstring)', "lxml.etree.parse/fromstring - XXE vulnerable by default, configure explicitly", "MEDIUM"),

    # --- File System Operations ---
    (r'open\s*\(.*?[\'"][wa][\'"]',    "open(..., 'w'/'a') - writes or appends to file",                             "MEDIUM"),
    (r'\bos\.(remove|unlink)\s*\(',    "os.remove/unlink() - deletes a file",                                        "MEDIUM"),
    (r'\bshutil\.rmtree\s*\(',         "shutil.rmtree() - recursively deletes a directory tree",                     "HIGH"),
    (r'\btempfile\.mktemp\s*\(',       "tempfile.mktemp() - insecure temp file creation (race condition)",            "MEDIUM"),
    (r'\.extractall\s*\(',             "extractall() - extracting archives without path validation enables Zip Slip", "HIGH"),

    # --- Network Requests ---
    (r'\brequests\.(post|put|delete|patch)\s*\(', "requests.post/put/delete/patch() - state-changing HTTP request",  "MEDIUM"),
    (r'\burllib.*urlopen\s*\(',        "urllib.urlopen() - network request, potential data exfiltration",             "MEDIUM"),
    (r'verify\s*=\s*False',            "verify=False - SSL certificate verification disabled (MITM risk)",            "MEDIUM"),

    # --- Hardcoded Credentials ---
    (r'(?i)(password|passwd|secret|api_key|token)\s*=\s*[\'"][^\'"]{4,}[\'"]',
                                       "Hardcoded credential - password/secret/token/api_key assigned a literal string value", "HIGH"),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
                                       "Hardcoded private key - private key material embedded directly in code",      "HIGH"),

    # --- Path Traversal ---
    (r'os\.path\.join\s*\(.*?(input|request|param|arg)',
                                       "os.path.join with user input - potential directory traversal vulnerability",  "MEDIUM"),

    # --- Weak Cryptography ---
    (r'\bhashlib\.(md5|sha1)\s*\(',    "hashlib.md5/sha1() - weak hash algorithm, insecure for security use",        "LOW"),
    (r'\brandom\.(random|randint|choice|shuffle)\s*\(',
                                       "random.* - not cryptographically secure, do not use for tokens/keys/passwords", "LOW"),
    (r'\biv\s*=\s*b?[\'"][^\'"]{8,}[\'"]',
                                       "Hardcoded IV - fixed initialization vector breaks semantic security of encryption", "MEDIUM"),
]

SHELL_PATTERNS: List[Tuple[str, str, str]] = [
    # --- Destructive Commands ---
    (r'rm\s+-[^\s]*r[^\s]*f|rm\s+-[^\s]*f[^\s]*r',
                                       "rm -rf - recursive force delete, unrecoverable",                             "HIGH"),
    (r'>\s*/dev/sd',                   ">/dev/sd* - writes directly to raw disk, destroys filesystem",               "HIGH"),
    (r'mv\s+\S+\s+/dev/null',          "mv ... /dev/null - moves files into void (equivalent to deletion)",          "HIGH"),

    # --- Privilege Escalation ---
    (r'\bsudo\s+',                     "sudo - executes command with superuser privileges",                          "HIGH"),
    (r'\bsu\s+',                       "su - switches to another user account",                                      "MEDIUM"),
    (r'\bchmod\s+(777|a\+w)',          "chmod 777/a+w - sets world-writable permissions",                            "HIGH"),
    (r'\bchmod\s+[uo]?\+s',            "chmod +s - sets SUID/SGID bit, can be used for privilege escalation",       "HIGH"),
    (r'\bcrontab\s+-',                 "crontab - modifying cron jobs can establish persistent backdoors",            "HIGH"),
    (r'\biptables\s+',                 "iptables - modifying firewall rules can expose malicious ports",              "HIGH"),

    # --- Remote Code Execution ---
    (r'(wget|curl)[^\n]*\|\s*(ba)?sh', "wget/curl | sh - downloads and executes remote script",                      "HIGH"),
    (r'base64[^\n]*\|\s*(ba)?sh',      "base64 | sh - base64-obfuscated payload executed via shell",                 "HIGH"),
    (r'\beval\s+',                     "eval - executes string as shell command, injection risk",                    "HIGH"),
    (r'\bnc\b.*-e\s+',                 "nc -e - netcat reverse shell, common attack payload",                        "HIGH"),

    # --- Persistence ---
    (r'\bnohup\s+',                    "nohup - detaches process from terminal, used for persistent backdoors",       "MEDIUM"),
]

MARKDOWN_PATTERNS: List[Tuple[str, str, str]] = [
    (r'rm\s+-rf',                      "rm -rf pattern found in SKILL.md instructions",                              "MEDIUM"),
    (r'\bsudo\s+',                     "sudo command found in SKILL.md instructions",                                "MEDIUM"),
    (r'\bchmod\s+777',                 "chmod 777 found in SKILL.md instructions",                                   "MEDIUM"),
    (r'(wget|curl)[^\n]*\|\s*(ba)?sh', "wget/curl | sh pattern in SKILL.md instructions",                           "HIGH"),
    (r'\beval\s+',                     "eval pattern found in SKILL.md instructions",                                "MEDIUM"),
    (r'base64[^\n]*\|\s*(ba)?sh',      "base64 | sh pattern found in SKILL.md instructions",                        "HIGH"),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
                                       "Private key material found in SKILL.md",                                     "HIGH"),
]


# ---------------------------------------------------------------------------

@dataclass
class Finding:
    location: str
    description: str
    severity: str
    line_no: int = 0
    snippet: str = ""


def scan_content(content: str, patterns: List[Tuple[str, str, str]], location: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = content.splitlines()
    for pattern, description, severity in patterns:
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                findings.append(Finding(
                    location=location,
                    description=description,
                    severity=severity,
                    line_no=i,
                    snippet=line.strip()[:120],
                ))
    return findings


def audit_skill(skill_path: str) -> None:
    if not os.path.exists(skill_path):
        print(f"Error: Skill path '{skill_path}' does not exist.")
        sys.exit(1)

    skill_md_path = os.path.join(skill_path, "SKILL.md")
    if not os.path.exists(skill_md_path):
        print(f"Error: SKILL.md not found in '{skill_path}'.")
        sys.exit(1)

    print(f"Auditing skill at: {skill_path}\n")
    all_findings: List[Finding] = []

    # ---- Analyze SKILL.md ----
    print("=" * 60)
    print("SKILL.md")
    print("=" * 60)
    with open(skill_md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    fm_match = re.search(r"^---\s*\n(.*?)\n---\s*\n", md_content, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        name_m = re.search(r"name:\s*(.+)", fm)
        desc_m = re.search(r"description:\s*(.+)", fm)
        print(f"  Name       : {name_m.group(1).strip() if name_m else 'N/A'}")
        print(f"  Description: {desc_m.group(1).strip() if desc_m else 'N/A'}")
    else:
        print("  Warning: No YAML frontmatter found.")

    md_findings = scan_content(md_content, MARKDOWN_PATTERNS, "SKILL.md")
    all_findings.extend(md_findings)
    if md_findings:
        print(f"\n  Found {len(md_findings)} potential risk(s) in SKILL.md:")
        for f in md_findings:
            print(f"  [{f.severity}] Line {f.line_no}: {f.description}")
            print(f"         > {f.snippet}")
    else:
        print("\n  No risky patterns found in SKILL.md.")

    # ---- Analyze Scripts ----
    scripts_dir = os.path.join(skill_path, "scripts")
    if os.path.isdir(scripts_dir):
        for root, _, files in os.walk(scripts_dir):
            for filename in sorted(files):
                ext = os.path.splitext(filename)[1].lower()
                if ext not in (".py", ".sh", ".js"):
                    continue
                script_path = os.path.join(root, filename)
                rel_path = os.path.relpath(script_path, skill_path)

                print(f"\n{'=' * 60}")
                print(f"Script: {rel_path}")
                print("=" * 60)

                try:
                    with open(script_path, "r", encoding="utf-8") as f:
                        code = f.read()
                except Exception as e:
                    print(f"  Could not read file: {e}")
                    continue

                if ext == ".py":
                    findings = scan_content(code, PYTHON_PATTERNS, rel_path)
                elif ext == ".sh":
                    findings = scan_content(code, SHELL_PATTERNS, rel_path)
                else:
                    # JS: basic check for eval/exec-like patterns
                    js_patterns = [p for p in PYTHON_PATTERNS if "eval" in p[0] or "exec" in p[0]]
                    findings = scan_content(code, js_patterns, rel_path)

                all_findings.extend(findings)
                if findings:
                    print(f"  Found {len(findings)} potential risk(s):")
                    for f in findings:
                        print(f"  [{f.severity}] Line {f.line_no}: {f.description}")
                        print(f"         > {f.snippet}")
                else:
                    print("  No risky patterns found.")
    else:
        print("\nNo scripts/ directory found.")

    # ---- Summary ----
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    high   = [f for f in all_findings if f.severity == "HIGH"]
    medium = [f for f in all_findings if f.severity == "MEDIUM"]
    low    = [f for f in all_findings if f.severity == "LOW"]
    print(f"  Total findings : {len(all_findings)}")
    print(f"  HIGH           : {len(high)}")
    print(f"  MEDIUM         : {len(medium)}")
    print(f"  LOW            : {len(low)}")

    if high:
        print("\n  HIGH severity findings require careful manual review before use.")
    elif medium:
        print("\n  MEDIUM severity findings detected. Review context before use.")
    else:
        print("\n  No HIGH/MEDIUM risks detected. Skill appears safe to use.")

    print("\nNote: This is static analysis only. Always manually review")
    print("      complex or obfuscated code before trusting a skill.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python audit_skill.py <path_to_skill_directory>")
        sys.exit(1)
    audit_skill(sys.argv[1])
