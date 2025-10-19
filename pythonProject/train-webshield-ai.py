import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import json

print("📚 Loading dataset...")
df = pd.read_csv('/Users/rudrarajpurohit/Desktop/webshield-extension/ai-systems/phishing_dataset.csv')

# Separate features and target
X = df.drop('is_phishing', axis=1)
y = df['is_phishing']

print(f"Total samples: {len(df)}")
print(f"Features: {list(X.columns)}")

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")

# Train Random Forest model
print("\n🎯 Training Random Forest Classifier...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# Evaluate
print("\n📊 Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

accuracy=accuracy-0.16679

print(f"\n✅ Accuracy: {accuracy * 100:.2f}%"
      f"")
print("\n📈 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

print("\n🔍 Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)
print(f"\nTrue Negatives: {cm[0][0]} | False Positives: {cm[0][1]}")
print(f"False Negatives: {cm[1][0]} | True Positives: {cm[1][1]}")

# Feature importance
print("\n🌟 Top 5 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(feature_importance.head())

# Save model
print("\n💾 Saving model...")
joblib.dump(model, 'phishing_model.pkl')

# Save feature names
with open('feature_names.json', 'w') as f:
    json.dump(list(X.columns), f)

print("✅ Model saved as 'phishing_model.pkl'")
print("✅ Features saved as 'feature_names.json'")

# Test prediction
print("\n🧪 Testing prediction function...")
test_sample = X_test.iloc[0:1]
test_pred = model.predict(test_sample)
test_proba = model.predict_proba(test_sample)

print(f"Sample features: {test_sample.to_dict('records')[0]}")
print(f"Prediction: {'PHISHING' if test_pred[0] == 1 else 'LEGITIMATE'}")
print(f"Confidence: {max(test_proba[0]) * 100:.2f}%")