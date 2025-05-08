import re
import pandas as pd

from sklearn.feature_extraction.text import (
    TfidfVectorizer,
 )

df = pd.read_csv("api_data_base.csv").drop(columns=["file_path"])
docs = df["file_content"].tolist()
labels = df["label"].values
token_pattern = re.compile(r"[\w\.]+")
tokenize = lambda txt: token_pattern.findall(txt)

tfidf = TfidfVectorizer(
    token_pattern=r"[\w\.]+", ngram_range=(1,2), min_df=5
)
X_tfidf = tfidf.fit_transform(docs)
tfidf_df = pd.DataFrame(
    X_tfidf.toarray(), columns=tfidf.get_feature_names_out()
)
tfidf_df["label"] = labels
tfidf_df.to_csv("api_data_tfidf.csv", index=False)
