import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_curve, roc_auc_score
import joblib
import os

# Create directory for figures if not exists
os.makedirs("M:\\Ransomware_Lab\\figures", exist_ok=True)

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
X_test = tfidf.transform(X_test_text)

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

print("Best params (RF):", gs_rf.best_params_)
y_pred = gs_rf.predict(X_test)
print(classification_report(y_test, y_pred))

# Get predicted probabilities for ROC curve
y_proba = gs_rf.predict_proba(X_test)[:, 1]  # Probability of positive class

# Calculate ROC curve metrics
fpr, tpr, thresholds = roc_curve(y_test, y_proba)
auc_score = roc_auc_score(y_test, y_proba)

# Plot ROC curve
plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {auc_score:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Chance')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve - Opcode Model')
plt.legend(loc="lower right")
plt.grid(True)

# Save and show plot
plt.savefig("M:\\Ransomware_Lab\\figures\\opcode_roc_curve.png", dpi=300, bbox_inches='tight')
plt.close()

# Save models
joblib.dump(tfidf, "M:\\Ransomware_Lab\\ransomware_llm_analyzer\\opc_ml\\opc_tfidf_vectorizer.joblib")
joblib.dump(gs_rf.best_estimator_, "M:\\Ransomware_Lab\\ransomware_llm_analyzer\\opc_ml\\opc_rf_model.joblib")
