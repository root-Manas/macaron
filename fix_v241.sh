#!/usr/bin/env python3
"""Apply v2.4.1 fixes to macaron - run: python3 fix_v241.sh"""
import shutil
import subprocess
import sys

# Backup
shutil.copy('macaron', 'macaron.bak')

with open('macaron', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix 1: Version bump
content = content.replace('VERSION = "2.4.0"', 'VERSION = "2.4.1"')

# Fix 2: Go tool name extraction
old_name = "        name = tool.split('/')[-1].split('@')[0]"
new_name = """        # Extract tool name properly (handle v2/v3/cmd paths)
        parts = tool.split('/')
        name = parts[-1].split('@')[0]
        if name in ('v2', 'v3', 'cmd'):
            for p in reversed(parts[:-1]):
                if p not in ('v2', 'v3', 'cmd'):
                    name = p
                    break"""
content = content.replace(old_name, new_name)

# Fix 3: Cargo check
old_x8 = '''    # x8 (Rust)
    console.print("  [dim]Installing[/] x8") if console else None
    subprocess.run(["cargo", "install", "x8"], capture_output=True)'''
new_x8 = '''    # x8 (Rust) - only if cargo is available
    if shutil.which("cargo"):
        console.print("  [dim]Installing[/] x8") if console else None
        subprocess.run(["cargo", "install", "x8"], capture_output=True)
    else:
        console.print("  [dim]Skipping[/] x8 (cargo not installed)") if console else None'''
content = content.replace(old_x8, new_x8)

with open('macaron', 'w', encoding='utf-8') as f:
    f.write(content)

# Verify
with open('macaron', 'r', encoding='utf-8') as f:
    c = f.read()

print("Checking fixes applied:")
print(f"  Version 2.4.1: {'✓' if '2.4.1' in c else '✗'}")
print(f"  Name fix: {'✓' if 'Extract tool name' in c else '✗'}")
print(f"  Cargo fix: {'✓' if 'cargo not installed' in c else '✗'}")

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
