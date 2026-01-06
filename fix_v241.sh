#!/usr/bin/env python3
"""Apply v2.4.1 fixes to macaron - run: python3 fix_v241.sh"""
import shutil
import subprocess
import sys
import re

# Backup
shutil.copy('macaron', 'macaron.bak')

with open('macaron', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Fix 1: Version bump
    if 'VERSION = "2.4.0"' in line:
        line = line.replace('VERSION = "2.4.0"', 'VERSION = "2.4.1"')
        new_lines.append(line)
        i += 1
        continue
    
    # Fix 2: Go tool name extraction - match exact context
    if "for tool in go_tools:" in line:
        new_lines.append(line)
        i += 1
        # Next line should be the name extraction
        if i < len(lines) and "name = tool.split('/')[-1].split('@')[0]" in lines[i]:
            # Replace with multi-line fix
            indent = "        "
            new_lines.append(f"{indent}# Extract tool name properly (handle v2/v3/cmd paths)\n")
            new_lines.append(f"{indent}parts = tool.split('/')\n")
            new_lines.append(f"{indent}name = parts[-1].split('@')[0]\n")
            new_lines.append(f"{indent}if name in ('v2', 'v3', 'cmd'):\n")
            new_lines.append(f"{indent}    for p in reversed(parts[:-1]):\n")
            new_lines.append(f"{indent}        if p not in ('v2', 'v3', 'cmd'):\n")
            new_lines.append(f"{indent}            name = p\n")
            new_lines.append(f"{indent}            break\n")
            i += 1  # Skip original line
        continue
    
    # Fix 3: Cargo check - match exact lines
    if line.strip() == "# x8 (Rust)":
        # Check next two lines match expected pattern
        if (i + 2 < len(lines) and 
            'console.print("  [dim]Installing[/] x8")' in lines[i+1] and
            'subprocess.run(["cargo", "install", "x8"]' in lines[i+2]):
            indent = "    "
            new_lines.append(f"{indent}# x8 (Rust) - only if cargo is available\n")
            new_lines.append(f"{indent}if shutil.which(\"cargo\"):\n")
            new_lines.append(f"{indent}    console.print(\"  [dim]Installing[/] x8\") if console else None\n")
            new_lines.append(f"{indent}    subprocess.run([\"cargo\", \"install\", \"x8\"], capture_output=True)\n")
            new_lines.append(f"{indent}else:\n")
            new_lines.append(f"{indent}    console.print(\"  [dim]Skipping[/] x8 (cargo not installed)\") if console else None\n")
            i += 3  # Skip original 3 lines
            continue
    
    new_lines.append(line)
    i += 1

with open('macaron', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

# Verify
with open('macaron', 'r', encoding='utf-8') as f:
    c = f.read()

print("Checking fixes applied:")
print(f"  Version 2.4.1: {'✓' if '2.4.1' in c else '✗'}")
print(f"  Name fix: {'✓' if 'Extract tool name' in c else '✗'}")
print(f"  Cargo fix: {'✓' if 'cargo not installed' in c else '✗'}")

# Verify syntax
print("\nVerifying syntax...")
result = subprocess.run(['python3', '-m', 'py_compile', 'macaron'], capture_output=True, text=True)
if result.returncode != 0:
    print(f"Syntax error: {result.stderr}")
    print("Restoring backup.")
    shutil.copy('macaron.bak', 'macaron')
    sys.exit(1)
print("  Syntax: ✓")

if '2.4.1' in c and 'Extract tool name' in c and 'cargo not installed' in c:
    print("\nAll fixes applied! Running tests...")
    result = subprocess.run(['python3', '-m', 'pytest', 'tests/', '-q'])
    if result.returncode == 0:
        print("\nTests passed. Committing...")
        subprocess.run(['git', 'add', 'macaron', 'fix_v241.sh'])
        subprocess.run(['git', 'commit', '-m', 'fix: v2.4.1 - Installer cargo check and Go name extraction'])
        subprocess.run(['git', 'push', 'origin', 'main'])
        print("Done!")
    else:
        print("Tests failed. Restoring backup.")
        shutil.copy('macaron.bak', 'macaron')
        sys.exit(1)
else:
    print("\nFixes not applied correctly. Restoring backup.")
    shutil.copy('macaron.bak', 'macaron')
    sys.exit(1)
