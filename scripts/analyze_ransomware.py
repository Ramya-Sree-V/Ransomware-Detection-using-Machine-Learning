import os
import hashlib
import subprocess

SAMPLES_DIR = os.path.expanduser("~/ransomware_analysis/samples")
RESULTS_DIR = os.path.expanduser("~/ransomware_analysis/analysis_results")

# Create results directory if it doesn't exist
os.makedirs(RESULTS_DIR, exist_ok=True)

def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
        return output.decode('utf-8', errors='replace')  # or 'ignore'
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {cmd}\n{e.output.decode('utf-8', errors='replace')}")
        return ""



# Walk through each subdirectory
for root, dirs, files in os.walk(SAMPLES_DIR):
    for file in files:
        if not file.endswith((".exe", ".dll", ".bin", ".vba", ".elf")):
            print(f"🚫 Skipping: {file}")
            continue

        full_path = os.path.join(root, file)
        print(f"🔍 Analyzing: {full_path}")

        sha256 = sha256sum(full_path)
        file_output = run_cmd(f"file '{full_path}'")
        strings_output = run_cmd(f"strings -n 6 '{full_path}' | head -n 100")
        r2_info = run_cmd(f"r2 -c 'iI~file; i~format' -q0 '{full_path}'")

        output_text = f"""
Filename: {file}
Path: {full_path}
SHA256: {sha256}

[FILE INFO]
{file_output.strip()}

[STRINGS - first 100 lines]
{strings_output.strip()}

[RADARE2 INFO]
{r2_info.strip()}
"""

        # Save the result in a text file
        result_file_path = os.path.join(RESULTS_DIR, f"{file}.txt")
        try:
            with open(result_file_path, "w") as f:
                f.write(output_text)
            print(f"✅ Saved analysis to {result_file_path}")
        except Exception as e:
            print(f"❌ Failed to save {file}: {e}")
