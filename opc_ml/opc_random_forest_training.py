import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib


df = pd.read_csv("M:\\Ransomware_Lab\\ransomware_llm_analyzer\\opc_ml\\opc_data_base.csv")
X_text = df["file_content"].tolist()
y = df["label"].values


X_train_text, X_test_text, y_train, y_test = train_test_split(
    X_text, y, test_size=0.1, stratify=y, random_state=42
)


tfidf = TfidfVectorizer(
    token_pattern=r"[\w\.]+",
    ngram_range=(1,2),
    min_df=5
)
X_train = tfidf.fit_transform(X_train_text)
X_test  = tfidf.transform(X_test_text)


param_grid = {
    "n_estimators": [100, 200],
    "max_depth": [None, 10, 20],
    "min_samples_split": [2, 5]
}
gs_rf = GridSearchCV(
    RandomForestClassifier(random_state=42),
    param_grid,
    cv=5,
    scoring="f1",
    n_jobs=-1,
    verbose=1
)
gs_rf.fit(X_train, y_train)


print("best params (RF):", gs_rf.best_params_)
y_pred = gs_rf.predict(X_test)
print(classification_report(y_test, y_pred))


joblib.dump(tfidf, "M:\\Ransomware_Lab\\ransomware_llm_analyzer\\opc_ml\\opc_tfidf_vectorizer.joblib")
joblib.dump(gs_rf.best_estimator_, "M:\\Ransomware_Lab\\ransomware_llm_analyzer\\opc_ml\\opc_rf_model.joblib")
