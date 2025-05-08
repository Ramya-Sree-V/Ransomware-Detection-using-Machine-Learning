'''numpy~=1.24.4
scipy~=1.10.1
scikit-learn~=1.3.2
pandas~=2.0.3'''



import os
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

def process_files(directory, label):
    filenames, texts, labels = [], [], []
    for fn in os.listdir(directory):
        with open(os.path.join(directory, fn)) as f:
            texts.append(' '.join([l.strip() for l in f]))
        filenames.append(fn)
        labels.append(label)
    return filenames, texts, labels

# Process API data
benign_api = process_files('/home/miarv/ransomware_analysis/Vectorized/api/benign', 0)
ransom_api = process_files('/home/miarv/ransomware_analysis/Vectorized/api/ransomware', 1)

all_files = benign_api[0] + ransom_api[0]
all_texts = benign_api[1] + ransom_api[1]
all_labels = benign_api[2] + ransom_api[2]

# Vectorize API calls
api_vectorizer = CountVectorizer(binary=True)
X_api = api_vectorizer.fit_transform(all_texts)

# Save API features
pd.DataFrame({
    'filename': all_files,
    'vectorized_data': [','.join(map(str, x)) for x in X_api.toarray()],
    'label': all_labels
}).to_csv('api_vectors.csv', index=False)