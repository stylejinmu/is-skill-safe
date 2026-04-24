import os
import sys
import json
import re

def audit_skill(skill_path):
    if not os.path.exists(skill_path):
        print(f"Error: Skill path '{skill_path}' does not exist.")
        sys.exit(1)
        
    skill_md_path = os.path.join(skill_path, "SKILL.md")
    if not os.path.exists(skill_md_path):
        print(f"Error: SKILL.md not found in '{skill_path}'.")
        sys.exit(1)
        
    print(f"Auditing skill at: {skill_path}\n")
    
    # 1. Analyze SKILL.md
    print("--- SKILL.md Analysis ---")
    with open(skill_md_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Extract frontmatter
    frontmatter_match = re.search(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if frontmatter_match:
        print("Frontmatter found.")
        fm_content = frontmatter_match.group(1)
        if 'name:' in fm_content:
            name = re.search(r'name:\s*(.+)', fm_content).group(1)
            print(f"Name: {name}")
        if 'description:' in fm_content:
            desc = re.search(r'description:\s*(.+)', fm_content).group(1)
            print(f"Description: {desc}")
    else:
        print("Warning: No YAML frontmatter found.")
        
    # Check for potential risky commands in SKILL.md
    risky_patterns = [
        r'rm\s+-rf',
        r'sudo\s+',
        r'chmod\s+777',
        r'wget\s+.*\|.*sh',
        r'curl\s+.*\|.*sh',
        r'eval\s+',
        r'exec\s+'
    ]
    
    found_risks = []
    for pattern in risky_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            found_risks.append(f"Found potentially risky pattern '{match.group(0)}' in SKILL.md")
            
    if found_risks:
        print("\nPotential Risks in SKILL.md:")
        for risk in found_risks:
            print(f"- {risk}")
    else:
        print("\nNo obvious risky patterns found in SKILL.md.")
        
    # 2. Analyze Scripts
    scripts_dir = os.path.join(skill_path, "scripts")
    if os.path.exists(scripts_dir) and os.path.isdir(scripts_dir):
        print("\n--- Scripts Analysis ---")
        for root, _, files in os.walk(scripts_dir):
            for file in files:
                if file.endswith(('.py', '.sh', '.js')):
                    script_path = os.path.join(root, file)
                    print(f"\nAnalyzing script: {os.path.relpath(script_path, skill_path)}")
                    
                    with open(script_path, 'r', encoding='utf-8') as f:
                        script_content = f.read()
                        
                    script_risks = []
                    
                    # Python specific risks
                    if file.endswith('.py'):
                        py_risks = [
                            (r'os\.system\(', "os.system call"),
                            (r'subprocess\.Popen\(', "subprocess.Popen call"),
                            (r'subprocess\.run\(', "subprocess.run call"),
                            (r'eval\(', "eval() call"),
                            (r'exec\(', "exec() call"),
                            (r'__import__\(', "__import__() call"),
                            (r'open\(.*[\'"]w[\'"]\)', "File write operation"),
                            (r'requests\.(post|put|delete)', "HTTP state-changing request")
                        ]
                        for pattern, desc in py_risks:
                            if re.search(pattern, script_content):
                                script_risks.append(desc)
                                
                    # Shell specific risks
                    elif file.endswith('.sh'):
                        sh_risks = [
                            (r'rm\s+-rf', "Recursive force remove"),
                            (r'sudo\s+', "Sudo command"),
                            (r'chmod\s+777', "Insecure permissions"),
                            (r'>\s*/dev/sda', "Direct disk write")
                        ]
                        for pattern, desc in sh_risks:
                            if re.search(pattern, script_content):
                                script_risks.append(desc)
                                
                    if script_risks:
                        print("Potential Risks:")
                        for risk in script_risks:
                            print(f"- {risk}")
                    else:
                        print("No obvious risky patterns found.")
    else:
        print("\nNo scripts directory found.")
        
    print("\n--- Summary ---")
    print("Please review the findings above to determine if the skill is safe to use.")
    print("Note: This is a static analysis tool and may not catch all potential security issues.")
    print("Always manually review complex or obfuscated code.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python audit_skill.py <path_to_skill_directory>")
        sys.exit(1)
        
    audit_skill(sys.argv[1])
