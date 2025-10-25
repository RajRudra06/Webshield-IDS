import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import joblib
from pathlib import Path
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

import sys, os

# Compute absolute path to the project root (webshield-extension)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


# ---------------------------------------------------------
# Import your existing base model functions
# ---------------------------------------------------------
from fastapi_backend.app.utils.inferenceScripts.lgm_inference import process_url_with_heuristic_lightgbm
from fastapi_backend.app.utils.inferenceScripts.xgb_inference import process_url_with_heuristic_xgboost
from fastapi_backend.app.utils.inferenceScripts.rf_inference import process_url_with_heuristic_rf
# ---------------------------------------------------------
# Config
# ---------------------------------------------------------
DATA_PATH = "/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/meta_learning.csv"
OUT_DIR = Path("meta_outputs")
OUT_DIR.mkdir(exist_ok=True)
CLASSES = ['benign', 'defacement', 'malware', 'phishing']
RANDOM_STATE = 42

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def probs_to_vector(prob_dict):
    """
    Return probabilities as numpy array in class order.
    Assumes probabilities are already normalized (sum to 1).
    """
    return np.array([prob_dict.get(c, 0.0) for c in CLASSES], dtype=float)

def get_all_model_probs(url):

    try:
        # Run all 3 models
        xgb_result = process_url_with_heuristic_xgboost(url)
        lgb_result = process_url_with_heuristic_lightgbm(url)
        rf_result  = process_url_with_heuristic_rf(url)

        # Safely extract probabilities
        def extract_probs(result):
            # Try final_probabilities first; fallback to model_probabilities
            probs = result.get("final_probabilities") or result.get("model_probabilities")
            if not probs:
                # If something is wrong, default to uniform
                probs = {c: 0.25 for c in ['benign','defacement','malware','phishing']}
            return probs_to_vector(probs)

        xgb_probs = extract_probs(xgb_result)
        lgb_probs = extract_probs(lgb_result)
        rf_probs  = extract_probs(rf_result)

        return np.concatenate([xgb_probs, lgb_probs, rf_probs])

    except Exception as e:
        print(f"[WARN] Error processing {url}: {e}")
        # Return neutral vector if any model call fails
        return np.full(12, 0.25, dtype=float)

# ---------------------------------------------------------
# 1. Load & Analyze Data
# ---------------------------------------------------------
print("=" * 60)
print("STEP 1: Loading and Analyzing Data")
print("=" * 60)

df = pd.read_csv(DATA_PATH)
assert {'url', 'type'}.issubset(df.columns), "Dataset must have 'url' and 'type' columns"

print(f"\nTotal samples: {len(df)}")
print("\nClass distribution:")
print(df['type'].value_counts())
print("\nClass percentages:")
print(df['type'].value_counts(normalize=True) * 100)

# Stratified split
train_df, test_df = train_test_split(
    df, 
    stratify=df['type'], 
    test_size=0.2, 
    random_state=RANDOM_STATE
)

print(f"\nTrain set: {len(train_df)} samples")
print(f"Test set: {len(test_df)} samples")

# ---------------------------------------------------------
# 2. Build Meta-Features
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 2: Extracting Base Model Predictions")
print("=" * 60)

print("\nCollecting predictions from LightGBM, XGBoost, and Random Forest...")
print("This may take a few minutes...")

print("\n[1/2] Processing training URLs...")
X_train_list = []
for url in tqdm(train_df['url'].values, desc="Train", ncols=80):
    X_train_list.append(get_all_model_probs(url))
X_train = np.vstack(X_train_list)
y_train = train_df['type'].map(lambda c: CLASSES.index(c)).values

print("\n[2/2] Processing test URLs...")
X_test_list = []
for url in tqdm(test_df['url'].values, desc="Test", ncols=80):
    X_test_list.append(get_all_model_probs(url))
X_test = np.vstack(X_test_list)
y_test = test_df['type'].map(lambda c: CLASSES.index(c)).values

print(f"\nMeta-feature shapes:")
print(f"  X_train: {X_train.shape} (samples × features)")
print(f"  X_test: {X_test.shape}")

# ---------------------------------------------------------
# 3. Compute Class Weights
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 3: Computing Class Weights for Imbalance")
print("=" * 60)

class_weights = compute_class_weight(
    class_weight='balanced',
    classes=np.unique(y_train),
    y=y_train
)
class_weight_dict = dict(enumerate(class_weights))

print("\nClass weights (higher = more emphasis on minority class):")
for idx, cls in enumerate(CLASSES):
    print(f"  {cls:12s}: {class_weight_dict[idx]:.3f}")

# ---------------------------------------------------------
# 4. Train Meta-Model with Cross-Validation
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 4: Training Meta-Model (Logistic Regression)")
print("=" * 60)

meta = LogisticRegression(
    multi_class='multinomial',
    solver='lbfgs',
    C=1.0,  # Regularization (lower = more regularization)
    max_iter=2000,
    class_weight=class_weight_dict,  # Handle class imbalance
    random_state=RANDOM_STATE,
    verbose=0
)

# 5-fold cross-validation
print("\nPerforming 5-fold cross-validation...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

cv_scores_acc = cross_val_score(meta, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
cv_scores_f1 = cross_val_score(meta, X_train, y_train, cv=cv, scoring='f1_macro', n_jobs=-1)

print("\nCross-Validation Results:")
print(f"  Accuracy:  {cv_scores_acc.mean():.4f} ± {cv_scores_acc.std():.4f}")
print(f"  Macro-F1:  {cv_scores_f1.mean():.4f} ± {cv_scores_f1.std():.4f}")
print(f"  Individual folds (F1): {[f'{s:.4f}' for s in cv_scores_f1]}")

# Train on full training set
print("\nTraining on full training set...")
meta.fit(X_train, y_train)

# Save model
model_path = OUT_DIR / "meta_model.joblib"
joblib.dump(meta, model_path)
print(f"\n✓ Model saved to: {model_path}")

# ---------------------------------------------------------
# 5. Analyze Learned Weights
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 5: Analyzing Meta-Model Weights")
print("=" * 60)

feature_names = []
for model_name in ['XGBoost', 'LightGBM', 'RandomForest']:
    for cls in CLASSES:
        feature_names.append(f"{model_name}_{cls}")

print("\nLearned weights (for 'benign' class):")
benign_idx = CLASSES.index('benign')
benign_weights = meta.coef_[benign_idx]

# Sort by absolute weight
weight_importance = sorted(
    zip(feature_names, benign_weights),
    key=lambda x: abs(x[1]),
    reverse=True
)

print("\nTop 10 most influential features:")
for feat, weight in weight_importance[:10]:
    print(f"  {feat:25s}: {weight:+.4f}")

# ---------------------------------------------------------
# 6. Test Set Evaluation
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 6: Evaluating on Test Set")
print("=" * 60)

# Get predictions and probabilities
proba = meta.predict_proba(X_test)
preds = proba.argmax(axis=1)
max_probs = proba.max(axis=1)

# Overall metrics
acc = accuracy_score(y_test, preds)
f1_macro = f1_score(y_test, preds, average='macro')
f1_weighted = f1_score(y_test, preds, average='weighted')

print("\nOverall Performance:")
print(f"  Accuracy:       {acc:.4f} ({acc*100:.2f}%)")
print(f"  Macro F1:       {f1_macro:.4f}")
print(f"  Weighted F1:    {f1_weighted:.4f}")

# Per-class performance
print("\n" + "-" * 60)
print("Per-Class Performance:")
print("-" * 60)
print(classification_report(y_test, preds, target_names=CLASSES, digits=4))

# Confusion matrix
print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, preds)
print(cm)
print("\nRow = True class, Column = Predicted class")

# ---------------------------------------------------------
# 7. Confidence Analysis
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 7: Confidence Distribution Analysis")
print("=" * 60)

def get_confidence_level(prob):
    if prob > 0.85:
        return 'HIGH'
    elif prob > 0.60:
        return 'MEDIUM'
    else:
        return 'LOW'

confidence_levels = [get_confidence_level(p) for p in max_probs]
confidence_counts = pd.Series(confidence_levels).value_counts()

print("\nConfidence Distribution:")
for level in ['HIGH', 'MEDIUM', 'LOW']:
    count = confidence_counts.get(level, 0)
    pct = count / len(max_probs) * 100
    print(f"  {level:7s}: {count:5d} samples ({pct:5.2f}%)")

print("\nRecommended Actions:")
print("  HIGH (>85%):   Block/Allow immediately (frontend)")
print("  MEDIUM (60-85%): Allow with warning (frontend)")
print("  LOW (<60%):    Send to backend for deep analysis")

# ---------------------------------------------------------
# 8. Identify Difficult Cases
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 8: Analyzing Difficult Cases")
print("=" * 60)

# Find misclassified samples
misclassified_mask = (preds != y_test)
misclassified_indices = np.where(misclassified_mask)[0]

print(f"\nTotal misclassified: {len(misclassified_indices)} / {len(y_test)} ({len(misclassified_indices)/len(y_test)*100:.2f}%)")

if len(misclassified_indices) > 0:
    # Show a few examples
    print("\nExample misclassifications (first 5):")
    for i in misclassified_indices[:5]:
        true_label = CLASSES[y_test[i]]
        pred_label = CLASSES[preds[i]]
        conf = max_probs[i]
        url = test_df.iloc[i]['url']
        
        print(f"\n  URL: {url}")
        print(f"  True: {true_label}, Predicted: {pred_label} (confidence: {conf:.2%})")
        print(f"  Probabilities: {dict(zip(CLASSES, proba[i]))}")

# Low confidence correct predictions
low_conf_correct = (max_probs < 0.60) & (~misclassified_mask)
print(f"\nLow confidence but correct: {low_conf_correct.sum()} samples")
print("  → These should be sent to backend for confirmation")

# ---------------------------------------------------------
# 9. Save Outputs
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("STEP 9: Saving Results")
print("=" * 60)

# Save feature arrays
np.save(OUT_DIR / "X_train_meta.npy", X_train)
np.save(OUT_DIR / "y_train_meta.npy", y_train)
np.save(OUT_DIR / "X_test_meta.npy", X_test)
np.save(OUT_DIR / "y_test_meta.npy", y_test)

# Save predictions for analysis
results_df = pd.DataFrame({
    'url': test_df['url'].values,
    'true_label': [CLASSES[i] for i in y_test],
    'predicted_label': [CLASSES[i] for i in preds],
    'confidence': max_probs,
    'confidence_level': confidence_levels,
    'correct': ~misclassified_mask
})
results_df.to_csv(OUT_DIR / "test_predictions.csv", index=False)

print(f"\n✓ Feature matrices saved to: {OUT_DIR}")
print(f"✓ Test predictions saved to: {OUT_DIR / 'test_predictions.csv'}")

# ---------------------------------------------------------
# 10. Summary
# ---------------------------------------------------------
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)

print(f"""
✓ Meta-model trained successfully!

Key Metrics:
  - Test Accuracy: {acc:.4f} ({acc*100:.2f}%)
  - Macro F1-Score: {f1_macro:.4f}
  - High Confidence Predictions: {confidence_counts.get('HIGH', 0)/len(max_probs)*100:.1f}%
  
Model Performance vs Base Models:
  - LightGBM (individual): 97.03%
  - XGBoost (individual):  96.44%
  - Meta-Ensemble:         {acc*100:.2f}%
  - Improvement:           {(acc*100 - 97.03):.2f}%

Next Steps:
  1. Deploy meta_model.joblib to backend
  2. Use confidence thresholds for decision logic
  3. Monitor misclassified cases for retraining
  4. Consider adding context features (WHOIS, SSL) if confidence low

Output Directory: {OUT_DIR.resolve()}
""")

print("=" * 60)
print("Training Complete!")
print("=" * 60)