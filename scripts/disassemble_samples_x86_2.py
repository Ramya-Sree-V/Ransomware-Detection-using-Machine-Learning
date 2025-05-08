import os
import subprocess
import r2pipe

# Paths for the sample and disassembly directories
SAMPLES_DIR = os.path.expanduser("~/ransomware_analysis/classified/x86_samples/")
DISASM_DIR = os.path.expanduser("~/ransomware_analysis/disassembly_results_x86_2/")

# Ensure output directory exists
os.makedirs(DISASM_DIR, exist_ok=True)

# Function to get resolved APIs from the binary
def get_resolved_apis(r2):
    r2.cmd("aaa")  # Analyze all
    imports = r2.cmdj("iij")  # Get the imported functions in JSON format
    resolved_api = {
        imp["plt"]: imp["name"]  # Mapping plt address to resolved API names
        for imp in imports
    }
    return resolved_api

# Function to run disassembly and resolve APIs
def run_disassembly(file_path, output_path):
    try:
        # Initialize r2pipe to analyze the binary
        r2 = r2pipe.open(file_path)

        # Get resolved API addresses
        resolved_api = get_resolved_apis(r2)

        # Run the disassembly and get it in JSON format for better parsing
        disasm_output = r2.cmdj("pdfj")  # Disassemble function (JSON format)
        
        # Open the output file for writing the disassembly and resolved API calls
        with open(output_path, "w") as out_file:
            # Write disassembly with resolved API names
            for func in disasm_output:
                out_file.write(f"Function: {func['name']} at {hex(func['offset'])}\n")
                for op in func['ops']:
                    if op.get("type") == "call":
                        target = op.get("ptr")
                        # Resolve API if possible
                        api_name = resolved_api.get(target, "Unknown API")
                        out_file.write(f"  Offset: {hex(op['offset'])} | call {api_name} at {hex(target)}\n")
                    else:
                        out_file.write(f"  Offset: {hex(op['offset'])} | {op['disasm']}\n")

        print(f"✅ Disassembled with resolved APIs: {os.path.basename(file_path)} → {output_path}")
    except subprocess.TimeoutExpired:
        print(f"⏱️ Timeout while disassembling {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Disassembly failed for {file_path}: {e}")
    except Exception as e:
        print(f"⚠️ An error occurred: {e}")

# Traverse the directory tree for sample files
for root, dirs, files in os.walk(SAMPLES_DIR):
    for file in files:
        if not file.endswith((".exe", ".elf")):
            continue

        full_path = os.path.join(root, file)
        output_filename = f"{file}.asm"
        output_path = os.path.join(DISASM_DIR, output_filename)

        run_disassembly(full_path, output_path)

print("\n🎉 All disassemblies with resolved APIs completed.")
