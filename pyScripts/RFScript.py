import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV, learning_curve
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, 
precision_recall_curve, f1_score)
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
warnings.filterwarnings('ignore')

# Load dataset
data = pd.read_csv('./urls_features_combined.csv')

print(f"Dataset shape: {data.shape}")
print(f"Columns: {list(data.columns)}")
print(f"Class distribution:\n{data['type'].value_counts()}")

# Handle missing values
num_features = data.select_dtypes(include=[np.number]).columns.tolist()
if 'type' in num_features:
    num_features.remove('type')
if 'url' in num_features:
    num_features.remove('url')

data[num_features] = data[num_features].fillna(data[num_features].median())

# Separate features and target
X = data.drop(['url', 'type'], axis=1)
y = data['type']

# Scale numerical features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler
joblib.dump(scaler, 'scaler.pkl')
print("✓ Scaler saved successfully")

# Split into training, validation, and test sets
X_train, X_temp, y_train, y_temp = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)

print(f"\nData split - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

# Handle class imbalance with SMOTE
print("\nApplying SMOTE for handling class imbalance...")
smote = SMOTE(random_state=42, k_neighbors=5)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

print(f"Original training set: {len(X_train)}")
print(f"Resampled training set: {len(X_train_resampled)}")
print(f"Class distribution after SMOTE:\n{pd.Series(y_train_resampled).value_counts()}")

# Compute class weights
classes = np.unique(y_train_resampled)
class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train_resampled)
class_weights_dict = dict(zip(classes, class_weights))

print(f"\nClass weights: {class_weights_dict}")

# Results tracking
results = {
    'baseline': {},
    'tuned': {},
    'ensemble': {},
    'threshold_optimized': {}
}

# Create and train Random Forest
print("\n" + "="*50)
print("Training Random Forest Model...")
print("="*50)

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42,
    n_jobs=-1,
    class_weight=class_weights_dict
)

rf.fit(X_train_resampled, y_train_resampled)
print("✓ Model training completed")

# Validation set evaluation
y_val_pred = rf.predict(X_val)
val_accuracy = accuracy_score(y_val, y_val_pred)
print(f"\nValidation Accuracy: {val_accuracy:.4f}")
results['baseline']['val_accuracy'] = val_accuracy

# Learning curves
print("\nGenerating learning curves...")
train_sizes, train_scores, val_scores = learning_curve(
    rf, X_train_resampled, y_train_resampled, 
    cv=5, 
    scoring='f1_weighted',
    train_sizes=np.linspace(0.1, 1.0, 10),
    n_jobs=-1,
    random_state=42
)

plt.figure(figsize=(10, 6))
train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)
val_mean = np.mean(val_scores, axis=1)
val_std = np.std(val_scores, axis=1)

plt.plot(train_sizes, train_mean, label='Training score', color='blue', marker='o')
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.15, color='blue')
plt.plot(train_sizes, val_mean, label='Cross-validation score', color='red', marker='s')
plt.fill_between(train_sizes, val_mean - val_std, val_mean + val_std, alpha=0.15, color='red')

plt.xlabel('Training Set Size')
plt.ylabel('F1 Score (Weighted)')
plt.title('Learning Curves - Random Forest URL Classifier')
plt.legend(loc='lower right')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('learning_curves.png', dpi=300)
print("✓ Learning curves saved as 'learning_curves.png'")

# Make predictions on test set
y_pred = rf.predict(X_test)
y_proba = rf.predict_proba(X_test)

np.save('rf_probabilities.npy', y_proba)

# Threshold optimization (for multi-class, we skip this)
print("\n" + "="*50)
print("Multi-class Classification (No threshold optimization needed)")
print("="*50)

optimal_threshold = 0.5
print(f"Using default threshold: {optimal_threshold:.4f}")
print(f"Classes detected: {list(classes)}")

# Model evaluation
print("\n" + "="*50)
print("MODEL PERFORMANCE METRICS")
print("="*50)

print(f"\nTest Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.title('Confusion Matrix - URL Classification')
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=300)
print("✓ Confusion matrix saved as 'confusion_matrix.png'")

results['baseline']['test_accuracy'] = accuracy_score(y_test, y_pred)
results['baseline']['f1_score'] = f1_score(y_test, y_pred, average='weighted')

# Error analysis
print("\n" + "="*50)
print("ERROR ANALYSIS")
print("="*50)

misclassified_idx = np.where(y_pred != y_test)[0]
print(f"\nTotal misclassified samples: {len(misclassified_idx)} ({len(misclassified_idx)/len(y_test)*100:.2f}%)")

if len(misclassified_idx) > 0:
    false_positives = np.where((y_pred == 1) & (y_test == 0))[0]
    false_negatives = np.where((y_pred == 0) & (y_test == 1))[0]
    
    print(f"False Positives: {len(false_positives)}")
    print(f"False Negatives: {len(false_negatives)}")

# Feature importance
print("\n" + "="*50)
print("FEATURE IMPORTANCE ANALYSIS")
print("="*50)

feature_importances = pd.Series(rf.feature_importances_, index=X.columns)
feature_importances = feature_importances.sort_values(ascending=False)

print("\nTop 10 Most Important Features:")
print(feature_importances.head(10))

plt.figure(figsize=(10, 8))
top_features = feature_importances.head(15)
sns.barplot(x=top_features.values, y=top_features.index, palette='viridis')
plt.xlabel('Feature Importance')
plt.ylabel('Feature')
plt.title('Top 15 Feature Importances - Random Forest URL Classifier')
plt.tight_layout()
plt.savefig('feature_importances.png', dpi=300)
print("\n✓ Feature importance plot saved as 'feature_importances.png'")

# Save model with metadata
print("\n" + "="*50)
print("SAVING MODEL ARTIFACTS")
print("="*50)

MODEL_VERSION = "1.2.0"
metadata = {
    'version': MODEL_VERSION,
    'training_date': pd.Timestamp.now().strftime('%Y-%m-%d'),
    'test_accuracy': float(accuracy_score(y_test, y_pred)),
    'f1_score': float(f1_score(y_test, y_pred, average='weighted')),
    'feature_count': X.shape[1],
    'training_samples': len(X_train_resampled),
    'class_distribution': dict(pd.Series(y_train_resampled).value_counts()),
    'optimal_threshold': float(optimal_threshold) if len(classes) == 2 else 0.5,
    'hyperparameters': rf.get_params()
}

model_artifact = {
    'model': rf,
    'scaler': scaler,
    'metadata': metadata,
    'feature_names': list(X.columns),
    'results': results
}

joblib.dump(model_artifact, f'rf_url_classifier_v{MODEL_VERSION}.pkl')
print(f"✓ Model saved as 'rf_url_classifier_v{MODEL_VERSION}.pkl'")

results_df = pd.DataFrame(results).T
results_df.to_csv('experiment_results.csv')
print("✓ Experiment results saved as 'experiment_results.csv'")

print("\n" + "="*50)
print("TRAINING COMPLETED SUCCESSFULLY")
print("="*50)


# SECOND DRAFT

# # -----------------------------
# # Random Forest for URL Classification (Enhanced Version)
# # -----------------------------

# # 1. Import libraries
# import pandas as pd
# import numpy as np
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split, RandomizedSearchCV
# from sklearn.preprocessing import StandardScaler
# from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
# from sklearn.utils.class_weight import compute_class_weight
# import matplotlib.pyplot as plt
# import seaborn as sns
# import joblib  # For saving the trained model

# # -----------------------------
# # 2. Load dataset
# # -----------------------------
# # Assume CSV columns: Length, TLD, Num_Digits, Suspicious_Chars, Has_IP, Label
# data = pd.read_csv('urls_features.csv')

# # -----------------------------
# # 2a. Handle missing values
# # -----------------------------
# # Fill missing numerical features with median
# num_features = data.select_dtypes(include=[np.number]).columns.tolist()
# num_features.remove('Label')  # Exclude target
# data[num_features] = data[num_features].fillna(data[num_features].median())

# # -----------------------------
# # 2b. Encode categorical features if any (example: TLD)
# # -----------------------------
# # Convert categorical features to one-hot encoding
# cat_features = ['TLD']  # Add more if needed
# data = pd.get_dummies(data, columns=cat_features, drop_first=True)

# # -----------------------------
# # 2c. Separate features and target
# # -----------------------------
# X = data.drop('Label', axis=1)
# y = data['Label']

# # -----------------------------
# # 2d. Scale numerical features for neural networks compatibility (AE later)
# # -----------------------------
# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)

# # Optional: Save the scaler for future inference
# joblib.dump(scaler, 'scaler.pkl')

# # -----------------------------
# # 3. Split into training, validation, and test sets
# # -----------------------------
# X_train, X_temp, y_train, y_temp = train_test_split(
#     X_scaled, y, test_size=0.2, random_state=42, stratify=y
# )
# X_val, X_test, y_val, y_test = train_test_split(
#     X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
# )

# # -----------------------------
# # 4. Compute class weights to handle imbalanced dataset
# # -----------------------------
# classes = np.unique(y_train)
# class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
# class_weights_dict = dict(zip(classes, class_weights))

# # -----------------------------
# # 5. Create Random Forest with tuned hyperparameters (same as before + class_weight)
# # -----------------------------
# rf = RandomForestClassifier(
#     n_estimators=200,
#     max_depth=20,
#     min_samples_split=5,
#     min_samples_leaf=2,
#     max_features='sqrt',
#     random_state=42,
#     n_jobs=-1,
#     class_weight=class_weights_dict  # Added for imbalanced classes
# )

# # -----------------------------
# # 6. Optional: Hyperparameter tuning using RandomizedSearchCV
# # -----------------------------
# # Comment out if you want to use default hyperparameters
# # param_dist = {
# #     'n_estimators': [100, 200, 300],
# #     'max_depth': [10, 20, 30, None],
# #     'min_samples_split': [2, 5, 10],
# #     'min_samples_leaf': [1, 2, 4],
# #     'max_features': ['sqrt', 'log2', None]
# # }
# # rf_search = RandomizedSearchCV(rf, param_distributions=param_dist, n_iter=10, 
# #                                cv=3, verbose=2, n_jobs=-1, scoring='f1_weighted')
# # rf_search.fit(X_train, y_train)
# # rf = rf_search.best_estimator_

# # -----------------------------
# # 7. Train the model
# # -----------------------------
# rf.fit(X_train, y_train)

# # -----------------------------
# # 8. Make predictions
# # -----------------------------
# y_pred = rf.predict(X_test)

# # -----------------------------
# # 8a. Predict probabilities for ensemble with autoencoder
# # -----------------------------
# y_proba = rf.predict_proba(X_test)  # Shape: (num_samples, num_classes)
# # Optional: Save probabilities for AE weighting
# np.save('rf_probabilities.npy', y_proba)

# # -----------------------------
# # 9. Evaluate performance
# # -----------------------------
# print("Test Accuracy:", accuracy_score(y_test, y_pred))
# print("\nClassification Report:\n", classification_report(y_test, y_pred))
# print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# # -----------------------------
# # 10. Optional: ROC-AUC for multi-class (weighted)
# # -----------------------------
# # from sklearn.preprocessing import label_binarize
# # from sklearn.metrics import roc_auc_score
# # y_test_bin = label_binarize(y_test, classes=classes)
# # auc = roc_auc_score(y_test_bin, y_proba, average='weighted', multi_class='ovr')
# # print("Weighted ROC-AUC:", auc)

# # -----------------------------
# # 11. Feature importance
# # -----------------------------
# feature_importances = pd.Series(rf.feature_importances_, index=X.columns)
# feature_importances = feature_importances.sort_values(ascending=False)

# plt.figure(figsize=(10,8))
# sns.barplot(x=feature_importances, y=feature_importances.index)
# plt.title("Feature Importances")
# plt.show()

# # -----------------------------
# # 12. Save trained model
# # -----------------------------
# joblib.dump(rf, 'rf_url_classifier.pkl')
# print("Model saved as 'rf_url_classifier.pkl'")


# FIRST DRAFT

# # 1. Import libraries
# import pandas as pd
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# # -----------------------------
# # 2. Load dataset
# # Replace 'urls_features.csv' with your CSV file
# # Assume CSV columns: Length, TLD, Num_Digits, Suspicious_Chars, Has_IP, Label
# # Label: 0=Benign, 1=Phishing, 2=Malware
# # -----------------------------
# data = pd.read_csv('urls_features.csv')

# # Features
# X = data.drop('Label', axis=1)  # All columns except Label
# y = data['Label']               # Target column

# # -----------------------------
# # 3. Split into training and test sets
# # 80% train, 20% test
# # -----------------------------
# X_train, X_test, y_train, y_test = train_test_split(
#     X, y, test_size=0.2, random_state=42, stratify=y
# )

# # -----------------------------
# # 4. Create Random Forest with tuned hyperparameters
# # These are practical starting values
# # -----------------------------
# rf = RandomForestClassifier(
#     n_estimators=200,        # Number of trees
#     max_depth=20,            # Maximum depth of each tree
#     min_samples_split=5,     # Min samples to split a node
#     min_samples_leaf=2,      # Min samples in a leaf node
#     max_features='sqrt',     # Features considered at each split
#     random_state=42,
#     n_jobs=-1                # Use all CPU cores
# )

# # -----------------------------
# # 5. Train the model
# # -----------------------------
# rf.fit(X_train, y_train)

# # -----------------------------
# # 6. Make predictions
# # -----------------------------
# y_pred = rf.predict(X_test)

# # -----------------------------
# # 7. Evaluate performance
# # -----------------------------
# print("Test Accuracy:", accuracy_score(y_test, y_pred))
# print("\nClassification Report:\n", classification_report(y_test, y_pred))
# print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

# # -----------------------------
# # 8. Optional: Feature importance
# # -----------------------------
# import matplotlib.pyplot as plt
# import seaborn as sns

# feature_importances = pd.Series(rf.feature_importances_, index=X.columns)
# feature_importances = feature_importances.sort_values(ascending=False)

# plt.figure(figsize=(8,6))
# sns.barplot(x=feature_importances, y=feature_importances.index)
# plt.title("Feature Importances")
# plt.show()
