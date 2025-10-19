import sys
import json
import joblib
import pandas as pd
import numpy as np

# Load model and feature names
try:
    model = joblib.load('phishing_model.pkl')
    with open('feature_names.json', 'r') as f:
        feature_names = json.load(f)
except Exception as e:
    print(json.dumps({
        'error': f'Model loading failed: {str(e)}',
        'isPhishing': False,
        'confidence': 0
    }))
    sys.exit(1)

def predict(features_dict):
    """
    Predict if URL is phishing
    
    Args:
        features_dict: Dictionary with URL features
        
    Returns:
        dict: Prediction result with confidence
    """
    try:
        # Ensure all required features are present
        feature_vector = []
        for feature_name in feature_names:
            value = features_dict.get(feature_name, 0)
            feature_vector.append(value)
        
        # Convert to DataFrame (model expects this format)
        X = pd.DataFrame([feature_vector], columns=feature_names)
        
        # Predict
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        
        # Get confidence (probability of predicted class)
        confidence = probabilities[1] if prediction == 1 else probabilities[0]
        
        result = {
            'isPhishing': bool(prediction == 1),
            'confidence': float(confidence),
            'probabilities': {
                'legitimate': float(probabilities[0]),
                'phishing': float(probabilities[1])
            },
            'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE'
        }
        
        return result
        
    except Exception as e:
        return {
            'error': str(e),
            'isPhishing': False,
            'confidence': 0
        }

if __name__ == '__main__':
    # Read features from command line argument
    if len(sys.argv) > 1:
        features_json = sys.argv[1]
        features = json.loads(features_json)
    else:
        # Read from stdin
        features = json.loads(sys.stdin.read())
    
    # Make prediction
    result = predict(features)
    
    # Output as JSON
    print(json.dumps(result))