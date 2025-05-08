import os
import re

# 📂 Input/output dirs
input_dir = "/home/miarv/ransomware_analysis/Benign_samples/disassembly_benign/"
api_output_dir = "/home/miarv/ransomware_analysis/extracted_data/api_calls/benign"
opcode_output_dir = "/home/miarv/ransomware_analysis/extracted_data/opcodes/benign"

# Create output directories if they don't exist
os.makedirs(api_output_dir, exist_ok=True)
os.makedirs(opcode_output_dir, exist_ok=True)

# 🧠 Regex patterns
opcode_pattern = re.compile(r'^\s*0x[0-9a-f]+(?:\s+[0-9a-f]{2,}\s+)?([a-z]+)', re.IGNORECASE)
api_call_pattern = re.compile(r'\b(?:call|jmp)\b.*(?:\[)?(sym\.imp\.[\w\d_.]+)(?:\])?', re.IGNORECASE)

# 🚀 Iterate files
files_processed = 0  # To track if any files are processed
for file in os.listdir(input_dir):
    print(f"Checking file: {file}")  # Debug line to see which files are being checked
    if not file.endswith((".txt", ".asm", ".dis")):  # Handle .asm and other possible extensions
        print(f"Skipping {file} (Not a .txt, .asm or .dis file)")  # Debug line
        continue

    opcodes = []
    apis = []  # Using a list to preserve the order of appearance

    file_path = os.path.join(input_dir, file)
    with open(file_path, 'r', errors='ignore') as f:
        print(f"Opened file: {file_path}")  # Debug line to check if file is opening
        for line in f:
            # Extract opcode
            op_match = opcode_pattern.search(line)
            if op_match:
                opcodes.append(op_match.group(1))

            # Extract API call
            api_match = api_call_pattern.search(line)
            if api_match:
                apis.append(api_match.group(1))  # Store API calls, including duplicates

    if opcodes or apis:  # Only save if there are opcodes or APIs extracted
        base = os.path.splitext(file)[0]
        
        # Save opcode data
        with open(os.path.join(opcode_output_dir, f"{base}.txt"), 'w') as f_out:
            f_out.write('\n'.join(opcodes))

        # Save API call data, keeping duplicates in order of appearance
        with open(os.path.join(api_output_dir, f"{base}.txt"), 'w') as f_api:
            f_api.write('\n'.join(apis))  # Writes API calls with duplicates

        print(f"[✔] Processed {file}: {len(opcodes)} opcodes, {len(apis)} API calls")
        files_processed += 1
    else:
        print(f"[❌] No opcodes or API calls found in {file}")

# If no files were processed
if files_processed == 0:
    print("No files were processed. Please check the input folder and the file content.")
else:
    print("🎉 Done extracting opcodes and API calls!")
