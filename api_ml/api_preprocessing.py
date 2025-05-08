import os
import csv
import pandas as pd


src_dir = "data/api_calls"
output_csv = "api_data_base.csv"

data = []


benign_dir = os.path.join(src_dir, "benign")
if os.path.exists(benign_dir):
    for filename in os.listdir(benign_dir):
        file_path = os.path.join(benign_dir, filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    if content:
                        data.append({
                            'file_path': file_path,
                            'file_content': content,
                            'label': 0  
                        })
            except Exception as e:
                print(f"Error processing {file_path}: {e}")


ransom_dir = os.path.join(src_dir, "ransom")
if os.path.exists(ransom_dir):
    for filename in os.listdir(ransom_dir):
        file_path = os.path.join(ransom_dir, filename)
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    if content:
                        data.append({
                            'file_path': file_path,
                            'file_content': content,
                            'label': 1  # 1 for ransom
                        })
            except Exception as e:
                print(f"Error processing {file_path}: {e}")


if data:
    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False, quoting=csv.QUOTE_ALL)
    print(f"Successfully created {output_csv} with {len(data)} entries")
    print(f"Benign files: {sum(1 for item in data if item['label'] == 0)}")
    print(f"Ransom files: {sum(1 for item in data if item['label'] == 1)}")
else:
    print("No valid files found to process") 
