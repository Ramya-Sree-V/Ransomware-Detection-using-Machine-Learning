import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier


X = pd.read_csv("M:\\Ransomware_Lab\\ransomware_llm_analyzer\\api_ml\\api_data_tfidf.csv").drop(columns=["label"]).values
y = pd.read_csv("M:\\Ransomware_Lab\\ransomware_llm_analyzer\\api_ml\\api_data_tfidf.csv")["label"].values


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.1, stratify=y, random_state=42
)


print(f"train: {len(X_train)} ({len(X_train)/len(X):.0%}), "
      f"test: {len(X_test)} ({len(X_test)/len(X):.0%})")


# MultinomialNB
param_grid = {"alpha": [0.01, 0.1, 1.0, 10.0]}
gs_nb = GridSearchCV(
    MultinomialNB(),
    param_grid,
    cv=5,
    scoring="f1",
    n_jobs=-1,
    verbose=1
)
gs_nb.fit(X_train, y_train)

print("best params (NB):", gs_nb.best_params_)
y_pred = gs_nb.predict(X_test)
print(classification_report(y_test, y_pred))


# LinearSVC
param_grid = {"C": [0.01, 0.1, 1, 10]}
gs_svm = GridSearchCV(
    LinearSVC(max_iter=5000, random_state=42),
    param_grid,
    cv=5,
    scoring="f1",
    n_jobs=-1,
    verbose=1
)
gs_svm.fit(X_train, y_train)

print("best params (SVM):", gs_svm.best_params_)
y_pred = gs_svm.predict(X_test)
print(classification_report(y_test, y_pred))


# LogisticRegression
param_grid = {"C": [0.01, 0.1, 1, 10], "penalty": ["l2"], "solver": ["liblinear"]}
gs_lr = GridSearchCV(
    LogisticRegression(max_iter=2000, random_state=42),
    param_grid,
    cv=5,
    scoring="f1",
    n_jobs=-1,
    verbose=1
)
gs_lr.fit(X_train, y_train)

print("best params (LR):", gs_lr.best_params_)
y_pred = gs_lr.predict(X_test)
print(classification_report(y_test, y_pred))


# RandomForestClassifier
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
