import os
import subprocess

SAMPLES_DIR = os.path.expanduser("~/ransomware_analysis/samples")
DISASM_DIR = os.path.expanduser("~/ransomware_analysis/disassembly_results")

# Ensure output directory exists
os.makedirs(DISASM_DIR, exist_ok=True)

def run_disassembly(file_path, output_path):
    try:
        # Run r2 in headless mode, analyze all, then disassemble 1000 instructions
        cmd = f"r2 -c 'aaa; pd 1000' -q0 '{file_path}'"
        disasm_output = subprocess.check_output(cmd, shell=True, text=True, timeout=60)
        with open(output_path, "w") as out_file:
            out_file.write(disasm_output)
        print(f"✅ Disassembled: {os.path.basename(file_path)} → {output_path}")
    except subprocess.TimeoutExpired:
        print(f"⏱️ Timeout while disassembling {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Disassembly failed for {file_path}: {e}")

# Traverse the directory tree
for root, dirs, files in os.walk(SAMPLES_DIR):
    for file in files:
        if not file.endswith((".exe", ".elf")):
            continue

        full_path = os.path.join(root, file)
        output_filename = f"{file}.asm"
        output_path = os.path.join(DISASM_DIR, output_filename)

        run_disassembly(full_path, output_path)

print("\n🎉 All disassemblies completed.")
