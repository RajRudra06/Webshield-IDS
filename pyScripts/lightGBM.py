# CURRENT USED LIGHTGBM

import pandas as pd
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)
from sklearn.utils.class_weight import compute_class_weight
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

DATA_PATH = "/content/drive/MyDrive/Webshield Dataset/final_dataset_716k.csv"
RESULTS_DIR = "/content/drive/MyDrive/Webshield Dataset/LIGHTGBM 716k typosquatting "

os.makedirs(RESULTS_DIR, exist_ok=True)
print(f"✅ Results will be saved in: {RESULTS_DIR}")


data = pd.read_csv(DATA_PATH)

print(f"\nDataset shape: {data.shape}")
print(f"Columns: {list(data.columns)}")
print(f"Class distribution:\n{data['type'].value_counts()}")


num_features = data.select_dtypes(include=[np.number]).columns.tolist()
for col in ['type', 'url']:
    if col in num_features:
        num_features.remove(col)
data[num_features] = data[num_features].fillna(data[num_features].median())


X = data.drop(['url', 'type'], axis=1)
y = data['type']

feature_names = list(X.columns)
print("\n✓ Features prepared (no scaling needed for tree-based models)")


X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)

print(f"\nData split - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")


print("\nComputing class weights (LightGBM)...")
classes = np.unique(y_train)
class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
class_weights_dict = dict(zip(classes, class_weights))
print(f"Class weights: {class_weights_dict}")


print("\n" + "="*60)
print("🚀 Training LightGBM Model")
print("="*60)

lgbm = LGBMClassifier(
    n_estimators=500,
    learning_rate=0.05,
    num_leaves=64,
    max_depth=-1,
    subsample=0.8,
    colsample_bytree=0.8,
    class_weight=class_weights_dict,
    random_state=42,
    n_jobs=-1,
    verbose=-1
)

lgbm.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    eval_metric='multi_logloss'
)

print("✓ Model training completed")


y_val_pred = lgbm.predict(X_val)
val_accuracy = accuracy_score(y_val, y_val_pred)
print(f"\nValidation Accuracy: {val_accuracy:.4f}")


print("\n" + "="*60)
print("📊 MODEL PERFORMANCE (TEST SET)")
print("="*60)

y_pred = lgbm.predict(X_test)
y_proba = lgbm.predict_proba(X_test)
np.save(os.path.join(RESULTS_DIR, "lgbm_probabilities.npy"), y_proba)

test_accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
f1 = f1_score(y_test, y_pred, average='weighted')

print(f"Accuracy:  {test_accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")

# Save classification report
report = classification_report(y_test, y_pred, output_dict=True)
pd.DataFrame(report).transpose().to_csv(os.path.join(RESULTS_DIR, "lgbm_classification_report.csv"))
print("\nDetailed per-class report saved.")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
pd.DataFrame(cm).to_csv(os.path.join(RESULTS_DIR, "lgbm_confusion_matrix.csv"))
print("Confusion matrix saved.")


print("\n" + "="*60)
print("📈 TOP FEATURES CONTRIBUTING TO DECISIONS")
print("="*60)

feature_importances = pd.Series(
    lgbm.feature_importances_,
    index=feature_names
).sort_values(ascending=False)

print(feature_importances.head(15))
feature_importances.to_csv(os.path.join(RESULTS_DIR, "lgbm_feature_importance.csv"))
print("Feature importances saved.")


misclassified_idx = np.where(y_pred != y_test)[0]
error_pct = len(misclassified_idx) / len(y_test) * 100
print(f"\nMisclassified samples: {len(misclassified_idx)} ({error_pct:.2f}%)")


print("\n" + "="*60)
print("💾 SAVING MODEL ARTIFACTS")
print("="*60)

MODEL_VERSION = "1.3.0"
MODEL_PATH = os.path.join(RESULTS_DIR, f"lgbm_url_classifier_v{MODEL_VERSION}.pkl")

metadata = {
    'version': MODEL_VERSION,
    'training_date': pd.Timestamp.now().strftime('%Y-%m-%d'),
    'test_accuracy': float(test_accuracy),
    'precision_weighted': float(precision),
    'recall_weighted': float(recall),
    'f1_weighted': float(f1),
    'feature_count': X.shape[1],
    'training_samples': len(X_train),
    'class_distribution': dict(pd.Series(y_train).value_counts()),
    'hyperparameters': lgbm.get_params(),
    'notes': 'Tree-based model (no feature scaling required)'
}

model_artifact = {
    'model': lgbm,
    'metadata': metadata,
    'feature_names': feature_names
}

joblib.dump(model_artifact, MODEL_PATH)
print(f"✓ Model saved to: {MODEL_PATH}")


summary_path = os.path.join(RESULTS_DIR, "lgbm_summary.txt")
with open(summary_path, "w") as f:
    f.write(f"LightGBM Model Summary (v{MODEL_VERSION})\n")
    f.write("="*60 + "\n")
    f.write(f"Accuracy: {test_accuracy:.4f}\n")
    f.write(f"Precision: {precision:.4f}\n")
    f.write(f"Recall: {recall:.4f}\n")
    f.write(f"F1 Score: {f1:.4f}\n")
    f.write(f"Validation Accuracy: {val_accuracy:.4f}\n")
    f.write(f"Total features: {len(feature_names)}\n")
    f.write(f"Saved model path: {MODEL_PATH}\n")

print(f"\n✅ All results and artifacts saved in: {RESULTS_DIR}")
print("Training completed successfully.")
