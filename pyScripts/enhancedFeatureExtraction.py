import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from tldextract import extract
import math
from collections import Counter

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def shannon_entropy(s):
    """Calculate Shannon entropy of a string"""
    if len(s) == 0: 
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])

def longest_repeated_char(s):
    """Find longest sequence of repeated characters"""
    if not s:
        return 0
    max_count = count = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
    return max_count

def vowel_consonant_ratio(s):
    """Calculate ratio of vowels to consonants"""
    vowels = sum(1 for c in s.lower() if c in 'aeiou')
    consonants = sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')
    return vowels / consonants if consonants > 0 else 0

def get_tld_category(tld):
    """Categorize TLD by trust level"""
    high_trust_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil']
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz']
    
    if tld in high_trust_tlds:
        return 2  # High trust
    elif tld in suspicious_tlds:
        return 0  # Suspicious
    else:
        return 1  # Neutral

def count_ngrams(s, n=2):
    """Count character n-grams (useful for detecting randomness)"""
    if len(s) < n:
        return 0
    ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
    counter = Counter(ngrams)
    return len(counter)  # Unique n-grams

# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features_enhanced(url):
    """
    Extract 45+ features from URL
    Includes original 29 + 16 new critical features
    """
    features = {}
    
    try:
        parsed = urlparse(url)
        ext = extract(url)
        
        domain = ext.domain
        subdomain = ext.subdomain
        suffix = ext.suffix  # TLD
        path = parsed.path
        query = parsed.query
        netloc = parsed.netloc
        
        # ========================================
        # SECTION 1: BASIC STRUCTURAL (Original)
        # ========================================
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['num_special_chars'] = sum(url.count(c) for c in ['@','?','=','%','&','!','+','$'])
        features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', netloc)))
        
        # ========================================
        # SECTION 2: DOMAIN / HOST (Enhanced)
        # ========================================
        features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
        features['domain_length'] = len(domain)
        features['host_entropy'] = shannon_entropy(domain)
        
        # NEW: Domain lexical quality
        features['domain_has_digits'] = int(any(c.isdigit() for c in domain))
        features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
        features['domain_vowel_ratio'] = vowel_consonant_ratio(domain)
        features['domain_is_dictionary_word'] = int(domain.lower() in ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'youtube', 'twitter', 'instagram', 'linkedin', 'netflix', 'wikipedia', 'reddit', 'github', 'stackoverflow', 'medium', 'wordpress', 'yahoo', 'ebay', 'paypal', 'adobe', 'salesforce', 'spotify', 'pinterest', 'nike', 'walmart', 'target', 'intel', 'samsung', 'tesla', 'bmw', 'ford', 'shell', 'python', 'java', 'mozilla', 'chrome', 'firefox', 'opera', 'ubuntu', 'debian', 'mysql', 'oracle', 'docker', 'nginx', 'apache'])
        
        # ========================================
        # SECTION 3: TLD ANALYSIS (NEW - CRITICAL)
        # ========================================
        features['tld_length'] = len(suffix)
        features['tld_trust_category'] = get_tld_category(suffix.lower())
        features['is_suspicious_tld'] = int(suffix.lower() in ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'info', 'biz'])
        features['is_high_trust_tld'] = int(suffix.lower() in ['com', 'org', 'net', 'edu', 'gov', 'mil'])
        features['is_country_tld'] = int(len(suffix) == 2 and suffix.isalpha())  # .uk, .in, .jp
        
        # ========================================
        # SECTION 4: PATH / QUERY (Enhanced)
        # ========================================
        features['path_length'] = len(path)
        features['num_path_segments'] = len([p for p in path.split('/') if p])
        features['num_query_params'] = len(query.split('&')) if query else 0
        features['query_length'] = len(query)
        features['num_encoded_chars'] = url.count('%')
        features['num_fragments'] = url.count('#')
        
        # NEW: Path/Query analysis
        features['path_has_suspicious_ext'] = int(any(ext in path.lower() for ext in ['.exe', '.zip', '.apk', '.scr', '.bat', '.cmd']))
        features['query_has_redirect'] = int(any(word in query.lower() for word in ['redirect', 'url=', 'next=', 'continue=', 'return=']))
        
        # ========================================
        # SECTION 5: KEYWORD / LEXICAL (Enhanced)
        # ========================================
        suspicious_words = ['login', 'secure', 'update', 'account', 'verify', 'confirm', 'click', 'bank', 'paypal', 'signin', 'password', 'urgent', 'suspended', 'locked', 'expire', 'reward', 'prize', 'winner', 'claim', 'free']
        features['suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
        features['num_suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
        features['sensitive_word'] = int(any(word in url.lower() for word in ['bank', 'paypal', 'account', 'password', 'credit', 'card']))
        features['action_word'] = int(any(word in url.lower() for word in ['click', 'verify', 'confirm', 'update', 'download', 'install']))
        
        # NEW: Brand impersonation detection
        brand_names = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin', 'youtube', 'yahoo', 'ebay', 'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc', 'dhl', 'fedex', 'usps', 'irs', 'uscis']
        features['has_brand_name'] = int(any(brand in url.lower() for brand in brand_names))
        features['brand_not_in_domain'] = int(any(brand in url.lower() for brand in brand_names) and not any(brand in domain.lower() for brand in brand_names))
        
        # ========================================
        # SECTION 6: URL SHORTENERS (Original)
        # ========================================
        features['is_shortening_service'] = int(any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']))
        
        # ========================================
        # SECTION 7: CHARACTER ANALYSIS (Enhanced)
        # ========================================
        features['is_mixed_case'] = int(any(c.isupper() for c in url) and any(c.islower() for c in url))
        features['num_repeated_chars'] = longest_repeated_char(url)
        features['longest_token_length'] = max([len(t) for t in re.split(r'[./?=&_-]', url)]) if url else 0
        
        # NEW: Advanced character patterns
        features['digit_letter_ratio'] = features['num_digits'] / features['num_letters'] if features['num_letters'] > 0 else 0
        features['special_char_ratio'] = features['num_special_chars'] / len(url) if len(url) > 0 else 0
        features['uppercase_ratio'] = sum(1 for c in url if c.isupper()) / len(url) if len(url) > 0 else 0
        features['consecutive_consonants'] = max([len(m.group()) for m in re.finditer(r'[bcdfghjklmnpqrstvwxyz]+', url.lower())]) if url else 0
        
        # ========================================
        # SECTION 8: ENTROPY / RANDOMNESS (Enhanced)
        # ========================================
        features['url_entropy'] = shannon_entropy(url)
        features['path_entropy'] = shannon_entropy(path)
        features['domain_entropy'] = shannon_entropy(domain)
        
        # NEW: N-gram diversity (detects random strings)
        features['domain_bigram_diversity'] = count_ngrams(domain, 2) / len(domain) if len(domain) >= 2 else 0
        features['domain_trigram_diversity'] = count_ngrams(domain, 3) / len(domain) if len(domain) >= 3 else 0
        
        # ========================================
        # SECTION 9: ADVANCED SECURITY (Enhanced)
        # ========================================
        features['suspicious_prefix_suffix'] = int('-' in domain or domain.startswith('www-') or domain.startswith('m-'))
        features['num_suspicious_symbols'] = sum(domain.count(c) for c in ['@', '!', '*'])
        
        # NEW: Advanced patterns
        features['has_multiple_subdomains'] = int(features['num_subdomains'] >= 3)
        features['subdomain_length'] = len(subdomain) if subdomain else 0
        features['has_port'] = int(':' in netloc and not netloc.startswith('['))  # IPv6 exception
        features['uses_https'] = int(parsed.scheme == 'https')
        features['punycode_domain'] = int('xn--' in domain)  # IDN/Internationalized domain
        
        # ========================================
        # SECTION 10: STRUCTURAL RATIOS (NEW)
        # ========================================
        features['domain_url_ratio'] = len(domain) / len(url) if len(url) > 0 else 0
        features['path_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0
        features['query_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0
        
    except Exception as e:
        # If parsing fails, return default values
        print(f"Error processing URL: {url} - {str(e)}")
        features = {f'feature_{i}': 0 for i in range(45)}
    
    return features

# ============================================================
# BATCH PROCESSING
# ============================================================

def process_dataset(input_csv, output_csv):
    """
    Process entire dataset and save with features
    """
    print(f"📂 Loading dataset from: {input_csv}")
    data = pd.read_csv(input_csv)
    
    print(f"📊 Dataset shape: {data.shape}")
    print(f"📋 Columns: {data.columns.tolist()}")
    
    if 'url' not in data.columns:
        raise ValueError("Dataset must have 'url' column!")
    
    print(f"\n⚙️  Extracting features from {len(data)} URLs...")
    print("This may take several minutes...\n")
    
    # Extract features with progress
    features_list = []
    for idx, url in enumerate(data['url']):
        if idx % 10000 == 0:
            print(f"  Processed {idx}/{len(data)} URLs ({idx/len(data)*100:.1f}%)")
        features_list.append(extract_features_enhanced(url))
    
    features_df = pd.DataFrame(features_list)
    
    print(f"\n✅ Feature extraction complete!")
    print(f"📊 Total features extracted: {len(features_df.columns)}")
    
    # Combine with original data
    result_df = pd.concat([data, features_df], axis=1)
    
    # Save
    result_df.to_csv(output_csv, index=False)
    print(f"\n💾 Saved to: {output_csv}")
    print(f"📊 Final shape: {result_df.shape}")
    print(f"📋 Total columns: {len(result_df.columns)}")
    
    return result_df

# ============================================================
# USAGE EXAMPLE
# ============================================================

if __name__ == "__main__":
    # Process your dataset
    INPUT_FILE = '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/pyScripts/datasets/urls_raw_650k.csv'
    OUTPUT_FILE = 'urls_features_enhanced_v2.csv'
    
    df = process_dataset(INPUT_FILE, OUTPUT_FILE)
    
    # Show sample
    print("\n" + "="*60)
    print("SAMPLE OF EXTRACTED FEATURES:")
    print("="*60)
    print(df.head(3).to_string())