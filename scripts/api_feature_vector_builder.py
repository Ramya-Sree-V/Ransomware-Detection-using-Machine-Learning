import os
import csv
from collections import Counter

# 📁 Input directories
benign_api_dir = "/home/miarv/ransomware_analysis/extracted_data/api_calls/benign/"
ransom_api_dir = "/home/miarv/ransomware_analysis/extracted_data/api_calls/ransom/"

# 🧠 Get all unique API calls (feature space)
def get_all_api_features(*dirs):
    features = set()
    for d in dirs:
        for filename in os.listdir(d):
            if filename.endswith(".txt"):
                with open(os.path.join(d, filename), 'r', errors='ignore') as f:
                    for line in f:
                        features.add(line.strip())
    return sorted(features)

# 📊 Build frequency vectors per sample
def build_vectors(directory, label, feature_list):
    vectors = []
    for filename in os.listdir(directory):
        if not filename.endswith(".txt"):
            continue
        file_path = os.path.join(directory, filename)
        with open(file_path, 'r', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
            counts = Counter(lines)
            row = [counts.get(feature, 0) for feature in feature_list]
            row.append(label)
            vectors.append(row)
    return vectors

# 🚀 Execution
all_features = get_all_api_features(benign_api_dir, ransom_api_dir)

print(f"🔍 Total unique API call features: {len(all_features)}")

benign_data = build_vectors(benign_api_dir, "benign", all_features)
ransom_data = build_vectors(ransom_api_dir, "ransom", all_features)

all_data = benign_data + ransom_data
header = all_features + ["label"]

# 💾 Write to CSV
output_path = "/home/miarv/ransomware_analysis/extracted_data/api_features_dataset.csv"
with open(output_path, "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(all_data)

print(f"✅ Dataset written to: {output_path}")
