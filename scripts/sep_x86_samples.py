import os
import shutil
import pefile

# Set the source and destination directories
source_dir = '/home/miarv/ransomware_analysis/samples/'  # Root folder containing hash-named subfolders
destination_dir = '/home/miarv/ransomware_analysis/classified/x86_samples'  # Where you want to store x86 samples

# Ensure destination directory exists
if not os.path.exists(destination_dir):
    os.makedirs(destination_dir)

# Function to check if the file is x86
def is_x86(file_path):
    try:
        pe = pefile.PE(file_path)
        return pe.FILE_HEADER.Machine == 0x14c  # 0x14c == IMAGE_FILE_MACHINE_I386 (32-bit)
    except pefile.PEFormatError:
        return False

# Walk through each hash-named folder
for folder in os.listdir(source_dir):
    subfolder_path = os.path.join(source_dir, folder)
    
    if os.path.isdir(subfolder_path):
        sample_file = os.path.join(subfolder_path, f"{folder}.exe")  # Assuming file is named hash.exe
        
        if os.path.isfile(sample_file):
            if is_x86(sample_file):
                shutil.copy(sample_file, destination_dir)
                print(f"[+] Copied: {folder}.exe")
            else:
                print(f"[-] Skipped (not x86): {folder}.exe")
        else:
            print(f"[!] No .exe file found in: {subfolder_path}")

print("\n🎉 All done! x86 samples are now in the destination folder.")
