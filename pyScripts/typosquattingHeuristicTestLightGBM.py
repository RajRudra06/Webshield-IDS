"""
Post-Processing Heuristic Layer for Typosquatting Detection

This layer runs AFTER your LightGBM model prediction to catch
typosquatting cases that the model might miss (g00gle.com, faceb00k.com, etc.)

Usage:
    prediction, probability = model.predict(url)
    final_prediction, final_prob = apply_typosquatting_heuristic(url, prediction, probability)
"""

import re
from urllib.parse import urlparse
from tldextract import extract
from feature_utils import batch_extract_features,extract_features_enhanced
from difflib import SequenceMatcher
import pandas as pd
import numpy as np
import joblib

# ============================================================
# LEGITIMATE DOMAINS WHITELIST
# ============================================================

LEGITIMATE_DOMAINS = {
    # Google
    'google.com', 'google.co.in', 'google.co.uk', 'gmail.com',
    'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    
    # Facebook/Meta
    'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com',
    
    # Amazon
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazonaws.com',
    
    # Microsoft
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    
    # Apple
    'apple.com', 'icloud.com', 'me.com',
    
    # Others
    'paypal.com', 'netflix.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'reddit.com', 'github.com', 'yahoo.com',
    
    # Indian
    'flipkart.com', 'paytm.com', 'phonepe.com', 'icicibank.com',
    'hdfcbank.com', 'sbi.co.in', 'axisbank.com', 'kotak.com',
    'swiggy.com', 'zomato.com', 'irctc.co.in',
}

BRAND_NAMES = [
    'google', 'gmail', 'facebook', 'instagram', 'whatsapp', 'amazon',
    'microsoft', 'apple', 'paypal', 'netflix', 'twitter', 'linkedin',
    'youtube', 'reddit', 'github', 'yahoo', 'ebay', 'spotify',
    'flipkart', 'paytm', 'phonepe', 'icici', 'hdfc', 'sbi', 'axis',
    'kotak', 'swiggy', 'zomato', 'myntra', 'snapdeal'
]

# ============================================================
# TYPOSQUATTING DETECTION PATTERNS
# ============================================================

def generate_all_typosquatting_patterns(brand):
    """
    Generate ALL possible typosquatting variations
    
    Patterns covered:
    1. Character substitution: google → g00gle, go0gle, goog1e
    2. Character omission: google → gogle, googl, goole
    3. Character duplication: google → gooogle, googgle
    4. Character transposition: google → gogole, googel
    5. Homoglyphs: google → goog1e (l→1), goog|e
    """
    patterns = set()
    
    # Pattern 1: Character substitution (leetspeak)
    substitutions = {
        'o': ['0'],
        'i': ['1', '!', '|'],
        'l': ['1', '|'],
        'e': ['3'],
        'a': ['@', '4'],
        's': ['$', '5'],
        'g': ['9'],
        't': ['7'],
        'b': ['8']
    }
    
    # Single substitution
    for i, char in enumerate(brand):
        if char in substitutions:
            for replacement in substitutions[char]:
                variant = brand[:i] + replacement + brand[i+1:]
                patterns.add(variant)
    
    # Double substitution (common in phishing)
    for i, char1 in enumerate(brand):
        if char1 in substitutions:
            for j, char2 in enumerate(brand[i+1:], start=i+1):
                if char2 in substitutions:
                    for rep1 in substitutions[char1]:
                        for rep2 in substitutions[char2]:
                            variant = list(brand)
                            variant[i] = rep1
                            variant[j] = rep2
                            patterns.add(''.join(variant))
    
    # Pattern 2: Character omission
    if len(brand) > 4:  # Only for longer brands
        for i in range(len(brand)):
            variant = brand[:i] + brand[i+1:]
            patterns.add(variant)
    
    # Pattern 3: Character duplication
    for i in range(len(brand)):
        variant = brand[:i] + brand[i] + brand[i:]
        patterns.add(variant)
    
    # Pattern 4: Adjacent character transposition
    for i in range(len(brand) - 1):
        chars = list(brand)
        chars[i], chars[i+1] = chars[i+1], chars[i]
        patterns.add(''.join(chars))
    
    return patterns

def check_typosquatting_heuristic(domain_name):
    """
    Heuristic check for typosquatting
    
    Returns: (is_typosquatting, matched_brand, confidence)
    """
    domain_lower = domain_name.lower()
    
    # Quick check: If exactly legitimate, return immediately
    for legit in LEGITIMATE_DOMAINS:
        if domain_name == legit.split('.')[0]:
            return False, None, 0.0
    
    # Check each brand
    for brand in BRAND_NAMES:
        # Skip if exact match
        if domain_lower == brand:
            continue
        
        # Generate all typo patterns
        patterns = generate_all_typosquatting_patterns(brand)
        
        # Check if domain matches any pattern
        if domain_lower in patterns:
            return True, brand, 0.95  # High confidence
        
        # Check if pattern is part of domain (e.g., g00gle-secure)
        for pattern in patterns:
            if pattern in domain_lower:
                # But not if it's a legitimate compound
                if not any(legit.startswith(domain_lower) for legit in LEGITIMATE_DOMAINS):
                    return True, brand, 0.90
        
        # Additional check: High similarity with brand
        similarity = SequenceMatcher(None, domain_lower, brand).ratio()
        if 0.75 <= similarity < 1.0:
            # Check if it's not just a similar word
            if len(domain_lower) <= len(brand) + 2:
                return True, brand, similarity
    
    return False, None, 0.0

def check_homograph_attack(domain_name):
    """
    Detect homograph attacks (visually similar characters)
    
    Examples:
    - раypal.com (cyrillic 'а' instead of latin 'a')
    - goog1e.com (digit '1' instead of 'l')
    - facebo0k.com (digit '0' instead of 'o')
    """
    homoglyphs = {
        'a': ['а', '@', '4'],  # First one is cyrillic
        'o': ['о', '0'],       # First one is cyrillic
        'e': ['е', '3'],       # First one is cyrillic
        'i': ['і', '1', '!', '|'],
        'l': ['1', '|', 'I'],
        'c': ['с'],            # Cyrillic
        's': ['$', '5'],
        'b': ['8'],
        'g': ['9'],
        't': ['7'],
    }
    
    # Check if domain contains any homoglyphs
    for char in domain_name.lower():
        if not char.isalnum():
            continue
        # Check if this char is a homoglyph
        for original, replacements in homoglyphs.items():
            if char in replacements:
                # Found a potential homoglyph
                # Check if replacing it back matches a brand
                test_domain = domain_name.lower().replace(char, original)
                if any(brand in test_domain for brand in BRAND_NAMES):
                    return True, 0.85
    
    return False, 0.0

# ============================================================
# MAIN POST-PROCESSING FUNCTION
# ============================================================

def apply_typosquatting_heuristic(url, model_prediction, model_probabilities):
    """
    Apply post-processing heuristic layer
    
    Args:
        url: The URL string
        model_prediction: Prediction from your LightGBM model
        model_probabilities: Probability dict from model
        
    Returns:
        final_prediction: Corrected prediction
        final_probabilities: Adjusted probabilities
        detection_reason: Why it was flagged (for logging)
    """
    
    # Parse URL
    try:
        ext = extract(url)
        domain = ext.domain
        suffix = ext.suffix
        full_domain = f"{domain}.{suffix}".lower()
    except:
        # If parsing fails, trust model
        return model_prediction, model_probabilities, "parsing_error"
    
    # Step 1: If model says phishing with high confidence, trust it
    if model_prediction == 'phishing' and model_probabilities.get('phishing', 0) > 0.85:
        return model_prediction, model_probabilities, "model_confident"
    
    # Step 2: If exact legitimate domain, definitely benign
    if full_domain in LEGITIMATE_DOMAINS:
        return 'benign', {'benign': 0.999, 'phishing': 0.0005, 'malware': 0.0005, 'defacement': 0.0}, "whitelist_match"
    
    # Step 3: Check for typosquatting
    is_typo, matched_brand, typo_confidence = check_typosquatting_heuristic(domain)
    
    if is_typo and typo_confidence > 0.75:
        # Override model prediction
        return 'phishing', {
            'benign': 0.05,
            'phishing': 0.92,
            'malware': 0.02,
            'defacement': 0.01
        }, f"typosquatting_{matched_brand}"
    
    # Step 4: Check for homograph attacks
    is_homograph, homograph_conf = check_homograph_attack(domain)
    
    if is_homograph and homograph_conf > 0.75:
        return 'phishing', {
            'benign': 0.08,
            'phishing': 0.88,
            'malware': 0.03,
            'defacement': 0.01
        }, "homograph_attack"
    
    # Step 5: Combined heuristic for edge cases
    # If model says benign but domain looks suspicious
    if model_prediction == 'benign':
        suspicious_score = 0
        reasons = []
        
        # Check 1: Domain contains brand name but not exact match
        for brand in BRAND_NAMES:
            if brand in domain.lower() and full_domain not in LEGITIMATE_DOMAINS:
                suspicious_score += 0.3
                reasons.append(f"contains_{brand}")
        
        # Check 2: Domain has numbers mixed with letters (common in typosquatting)
        if any(c.isdigit() for c in domain) and any(c.isalpha() for c in domain):
            # Check if it's close to a brand
            for brand in BRAND_NAMES:
                domain_no_digits = ''.join(c for c in domain.lower() if not c.isdigit())
                if brand in domain_no_digits or SequenceMatcher(None, domain_no_digits, brand).ratio() > 0.75:
                    suspicious_score += 0.4
                    reasons.append("digits_in_brand")
                    break
        
        # Check 3: Very similar to brand (edit distance)
        for brand in BRAND_NAMES:
            if len(domain) <= len(brand) + 3:  # Similar length
                similarity = SequenceMatcher(None, domain.lower(), brand).ratio()
                if 0.75 <= similarity < 1.0:
                    suspicious_score += 0.3
                    reasons.append(f"similar_to_{brand}")
        
        # If cumulative suspicious score is high, flag as phishing
        if suspicious_score >= 0.6:
            return 'phishing', {
                'benign': 0.15,
                'phishing': 0.80,
                'malware': 0.03,
                'defacement': 0.02
            }, f"heuristic_{'_'.join(reasons)}"
    
    # Step 6: No heuristic triggered, trust model
    return model_prediction, model_probabilities, "model_decision"


# ============================================================
# BATCH PROCESSING WRAPPER
# ============================================================

def process_url_with_heuristic(url, model):
    """
    Complete pipeline: Model prediction + Heuristic correction
    
    Args:
        url: URL to check
        model: Your trained LightGBM model
        
    Returns:
        dict with prediction, probabilities, and detection info
    """

    artifact = joblib.load('/content/drive/MyDrive/Webshield Dataset/LIGHTGBM Results 716k typosquatting/lgbm_url_classifier_v1.3.0.pkl')
    model = artifact['model']
    features = artifact['feature_names']

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    X_dict = extract_features_enhanced(url)
    X = pd.DataFrame([X_dict])

    for col in features:
        if col not in X.columns:
            X[col] = 0
    X = X[features]

    model_pred = model.predict(X)[0]
    model_proba = model.predict_proba(X)[0]
    classes = model.classes_
    prob_dict = dict(zip(classes, model_proba))

    # # Step 1: Get model prediction
    # features = batch_extract_features(url)  # Your feature extraction
    # model_pred = model.predict([features])[0]
    # model_proba = model.predict_proba([features])[0]
    
    # # Convert to dict
    # classes = model.classes_
    # prob_dict = dict(zip(classes, model_proba))
    
    # Step 2: Apply heuristic layer
    final_pred, final_proba, reason = apply_typosquatting_heuristic(
        url, model_pred, prob_dict
    )
    
    return {
        'url': url,
        'model_prediction': model_pred,
        'model_probabilities': prob_dict,
        'final_prediction': final_pred,
        'final_probabilities': final_proba,
        'detection_reason': reason,
        'heuristic_applied': reason != "model_decision"
    }


# ============================================================
# TESTING FUNCTION
# ============================================================

def test_heuristic_layer():
    """
    Test the heuristic layer on known typosquatting cases
    """
    test_cases = [
        # Typosquatting that model misses
        ("https://www.g00gle.com", "phishing"),
        ("https://www.faceb00k.com", "phishing"),
        ("https://www.paypa1.com", "phishing"),
        ("https://www.microoft.com", "phishing"),
        ("https://www.arnazon.com", "phishing"),
        ("https://www.twiter.com", "phishing"),
        ("https://www.netfl1x.com", "phishing"),
        
        # Legitimate (should NOT be flagged)
        ("https://www.google.com", "benign"),
        ("https://www.facebook.com", "benign"),
        ("https://www.paypal.com", "benign"),
        
        # Edge cases
        ("https://www.googles.com", "benign"),  # Plural, legitimate
        ("https://www.googleapi.com", "benign"),  # Compound, legitimate
    ]
    
    print("="*70)
    print("HEURISTIC LAYER TEST")
    print("="*70)
    
    correct = 0
    total = len(test_cases)
    
    for url, expected in test_cases:
        # Simulate model prediction (assume benign for typos)
        model_pred = "benign"
        model_proba = {'benign': 0.95, 'phishing': 0.03, 'malware': 0.01, 'defacement': 0.01}
        
        # Apply heuristic
        final_pred, final_proba, reason = apply_typosquatting_heuristic(
            url, model_pred, model_proba
        )
        
        status = "✓" if final_pred == expected else "✗"
        if final_pred == expected:
            correct += 1
        
        print(f"\n{status} {url}")
        print(f"   Expected: {expected}")
        print(f"   Got: {final_pred} (reason: {reason})")
        print(f"   Confidence: {final_proba.get('phishing', 0):.2%}")
    
    print(f"\n{'='*70}")
    print(f"RESULTS: {correct}/{total} correct ({correct/total*100:.1f}%)")
    print(f"{'='*70}")


if __name__ == "__main__":
    test_heuristic_layer()