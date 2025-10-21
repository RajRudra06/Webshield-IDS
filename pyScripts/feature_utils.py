# """
# Script 2: Feature extraction utility functions
# Contains all helper functions and feature extraction logic
# Import this in other scripts to extract features
# """

# import pandas as pd
# import numpy as np
# import re
# from urllib.parse import urlparse
# from tldextract import extract
# import math
# from collections import Counter
# from difflib import SequenceMatcher

# # ============================================================
# # HELPER FUNCTIONS
# # ============================================================

# def shannon_entropy(s):
#     """Calculate Shannon entropy of a string"""
#     if not isinstance(s, str) or len(s) == 0:
#         return 0
#     s = ''.join(c for c in s if 32 <= ord(c) <= 126)  # remove control/non-ASCII chars
#     if len(s) == 0:
#         return 0
#     prob = [float(s.count(c)) / len(s) for c in set(s)]
#     return -sum([p * math.log2(p) for p in prob if p > 0])

# def longest_repeated_char(s):
#     """Find longest sequence of repeated characters"""
#     if not s:
#         return 0
#     max_count = count = 1
#     for i in range(1, len(s)):
#         if s[i] == s[i - 1]:
#             count += 1
#             max_count = max(max_count, count)
#         else:
#             count = 1
#     return max_count

# def vowel_consonant_ratio(s):
#     """Calculate ratio of vowels to consonants"""
#     vowels = sum(1 for c in s.lower() if c in 'aeiou')
#     consonants = sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')
#     return vowels / consonants if consonants > 0 else 0

# def get_tld_category(tld):
#     """Categorize TLD by trust level"""
#     high_trust_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in']
#     suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'buzz', 'loan']

#     if tld in high_trust_tlds:
#         return 2  # High trust
#     elif tld in suspicious_tlds:
#         return 0  # Suspicious
#     else:
#         return 1  # Neutral

# def count_ngrams(s, n=2):
#     """Count character n-grams (useful for detecting randomness)"""
#     if len(s) < n:
#         return 0
#     ngrams = [s[i:i + n] for i in range(len(s) - n + 1)]
#     counter = Counter(ngrams)
#     return len(counter)  # Unique n-grams

# # --- Safe helper functions for problematic max() calls ---

# def safe_max_len_list(values):
#     """Safely get max from list of lengths"""
#     try:
#         return max(values) if values else 0
#     except ValueError:
#         return 0

# def safe_max_match_length(pattern, text):
#     """Safely compute max regex match length"""
#     try:
#         matches = [len(m.group()) for m in re.finditer(pattern, text)]
#         return max(matches) if matches else 0
#     except Exception:
#         return 0

# # ============================================================
# # MAIN FEATURE EXTRACTION
# # ============================================================

# def extract_features_enhanced(url):
#     """
#     Extract 49+ features from URL (45 original + 4 new anti-phishing features)
#     Comprehensive feature set for phishing detection
    
#     Returns:
#         dict: Dictionary with 49+ feature values
#     """
#     features = {}

#     try:
#         if not isinstance(url, str) or len(url.strip()) == 0:
#             raise ValueError("Invalid or empty URL string")

#         # remove non-printable / corrupt characters
#         url = ''.join(c for c in url if 32 <= ord(c) <= 126)

#         parsed = urlparse(url)
#         ext = extract(url)

#         domain = ext.domain
#         subdomain = ext.subdomain
#         suffix = ext.suffix  # TLD
#         path = parsed.path
#         query = parsed.query
#         netloc = parsed.netloc

#         # ========================================
#         # SECTION 1: BASIC STRUCTURAL (10 features)
#         # ========================================
#         features['url_length'] = len(url)
#         features['num_dots'] = url.count('.')
#         features['num_hyphens'] = url.count('-')
#         features['num_underscores'] = url.count('_')
#         features['num_digits'] = sum(c.isdigit() for c in url)
#         features['num_letters'] = sum(c.isalpha() for c in url)
#         features['num_special_chars'] = sum(url.count(c) for c in ['@', '?', '=', '%', '&', '!', '+', '$'])
#         features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', netloc)))
#         features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
#         features['has_multiple_subdomains'] = int(features['num_subdomains'] >= 3)

#         # ========================================
#         # SECTION 2: DOMAIN ANALYSIS (12 features)
#         # ========================================
#         features['domain_length'] = len(domain)
#         features['host_entropy'] = shannon_entropy(domain)
#         features['domain_entropy'] = shannon_entropy(domain)
#         features['domain_has_digits'] = int(any(c.isdigit() for c in domain))
#         features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
#         features['domain_vowel_ratio'] = vowel_consonant_ratio(domain)
#         features['domain_bigram_diversity'] = count_ngrams(domain, 2) / len(domain) if len(domain) >= 2 else 0
#         features['domain_trigram_diversity'] = count_ngrams(domain, 3) / len(domain) if len(domain) >= 3 else 0
#         features['suspicious_prefix_suffix'] = int('-' in domain or domain.startswith('www-') or domain.startswith('m-'))
#         features['num_suspicious_symbols'] = sum(domain.count(c) for c in ['@', '!', '*'])
#         features['subdomain_length'] = len(subdomain) if subdomain else 0

#         # Known legitimate domains
#         known_legitimate_domains = [
#             'google', 'facebook', 'amazon', 'microsoft', 'apple', 'youtube', 'twitter', 'instagram',
#             'linkedin', 'netflix', 'wikipedia', 'reddit', 'github', 'stackoverflow', 'medium', 'wordpress',
#             'yahoo', 'ebay', 'paypal', 'adobe', 'salesforce', 'spotify', 'pinterest', 'tiktok',
#             'flipkart', 'myntra', 'snapdeal', 'meesho', 'ajio', 'nykaa', 'bigbasket', 'grofers',
#             'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'pnb', 'canara', 'bob', 'unionbank', 'idbi',
#             'paytm', 'phonepe', 'googlepay', 'bhim', 'mobikwik', 'freecharge', 'amazonpay',
#             'irctc', 'uidai', 'epfo', 'nsdl', 'swiggy', 'zomato', 'ola', 'uber', 'makemytrip', 'goibibo',
#             'nike', 'walmart', 'target', 'intel', 'samsung', 'tesla', 'bmw', 'ford', 'shell',
#             'python', 'java', 'mozilla', 'chrome', 'firefox', 'opera', 'ubuntu', 'debian',
#             'mysql', 'oracle', 'docker', 'nginx', 'apache'
#         ]
#         features['domain_is_dictionary_word'] = int(domain.lower() in known_legitimate_domains)

#         # ========================================
#         # SECTION 3: TLD ANALYSIS (5 features)
#         # ========================================
#         features['tld_length'] = len(suffix)
#         features['tld_trust_category'] = get_tld_category(suffix.lower())
#         features['is_suspicious_tld'] = int(suffix.lower() in ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'info', 'biz', 'buzz', 'loan'])
#         features['is_high_trust_tld'] = int(suffix.lower() in ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in'])
#         features['is_country_tld'] = int(len(suffix) == 2 and suffix.isalpha())

#         # ========================================
#         # SECTION 4: PATH/QUERY ANALYSIS (10 features)
#         # ========================================
#         features['path_length'] = len(path)
#         features['num_path_segments'] = len([p for p in path.split('/') if p])
#         features['num_query_params'] = len(query.split('&')) if query else 0
#         features['query_length'] = len(query)
#         features['num_encoded_chars'] = url.count('%')
#         features['num_fragments'] = url.count('#')
#         features['path_entropy'] = shannon_entropy(path)
#         features['path_has_suspicious_ext'] = int(any(ext in path.lower() for ext in ['.exe', '.zip', '.apk', '.scr', '.bat', '.cmd']))
#         features['query_has_redirect'] = int(any(word in query.lower() for word in ['redirect', 'url=', 'next=', 'continue=', 'return=']))
#         features['path_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0

#         # ========================================
#         # SECTION 5: KEYWORD/LEXICAL (8 features)
#         # ========================================
#         suspicious_words = ['login', 'secure', 'update', 'account', 'verify', 'confirm', 'click', 'bank', 'paypal',
#                             'signin', 'password', 'urgent', 'suspended', 'locked', 'expire', 'reward', 'prize',
#                             'winner', 'claim', 'free', 'wallet', 'kyc', 'blocked', 'reactivate']
#         features['suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
#         features['num_suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
#         features['sensitive_word'] = int(any(word in url.lower() for word in ['bank', 'paypal', 'account', 'password', 'credit', 'card', 'wallet', 'upi']))
#         features['action_word'] = int(any(word in url.lower() for word in ['click', 'verify', 'confirm', 'update', 'download', 'install']))

#         brand_names = [
#             'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix', 'instagram',
#             'twitter', 'linkedin', 'youtube', 'yahoo', 'ebay', 'chase', 'wellsfargo', 'citibank',
#             'hsbc', 'dhl', 'fedex', 'usps', 'irs', 'uscis',
#             'flipkart', 'paytm', 'phonepe', 'googlepay', 'icici', 'hdfc', 'sbi', 'axis', 'kotak',
#             'swiggy', 'zomato', 'ola', 'irctc', 'uidai', 'epfo', 'myntra', 'snapdeal', 'nykaa'
#         ]
#         features['has_brand_name'] = int(any(brand in url.lower() for brand in brand_names))
#         features['brand_not_in_domain'] = int(any(brand in url.lower() for brand in brand_names)
#                                               and not any(brand in domain.lower() for brand in brand_names))
#         features['is_shortening_service'] = int(any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']))
#         features['is_mixed_case'] = int(any(c.isupper() for c in url) and any(c.islower() for c in url))

#         # ========================================
#         # SECTION 6: CHARACTER PATTERNS (6 features)
#         # ========================================
#         features['num_repeated_chars'] = longest_repeated_char(url)
#         features['longest_token_length'] = safe_max_len_list([len(t) for t in re.split(r'[./?=&_-]', url)]) if url else 0
#         features['digit_letter_ratio'] = features['num_digits'] / features['num_letters'] if features['num_letters'] > 0 else 0
#         features['special_char_ratio'] = features['num_special_chars'] / len(url) if len(url) > 0 else 0
#         features['uppercase_ratio'] = sum(1 for c in url if c.isupper()) / len(url) if len(url) > 0 else 0
#         features['consecutive_consonants'] = safe_max_match_length(r'[bcdfghjklmnpqrstvwxyz]+', url.lower()) if url else 0

#         # ========================================
#         # SECTION 7: ENTROPY MEASURES (3 features)
#         # ========================================
#         features['url_entropy'] = shannon_entropy(url)

#         # ========================================
#         # SECTION 8: SECURITY INDICATORS (4 features)
#         # ========================================
#         features['has_port'] = int(':' in netloc and not netloc.startswith('['))
#         features['uses_https'] = int(parsed.scheme == 'https')
#         features['punycode_domain'] = int('xn--' in domain)
#         features['subdomain_count_dot'] = subdomain.count('.') if subdomain else 0

#         # ========================================
#         # SECTION 9: STRUCTURAL RATIOS (2 features)
#         # ========================================
#         features['domain_url_ratio'] = len(domain) / len(url) if len(url) > 0 else 0
#         features['query_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0

#         # ========================================
#         # SECTION 10: NEW ANTI-PHISHING FEATURES (4 features)
#         # ========================================
        
#         # Feature 1: Brand + Hyphen Detection
#         brand_with_hyphen_patterns = [
#             'google-', 'facebook-', 'amazon-', 'paypal-', 'netflix-', 'apple-',
#             'microsoft-', 'flipkart-', 'paytm-', 'icici-', 'hdfc-', 'sbi-',
#             'axis-', 'kotak-', 'swiggy-', 'zomato-'
#         ]
#         features['brand_with_hyphen'] = int(any(p in domain.lower() for p in brand_with_hyphen_patterns))
        
#         # Feature 2: Better Brand Impersonation Detection
#         full_domain = f"{domain}.{suffix}".lower()
#         legitimate_domains = [
#             'google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'netflix.com',
#             'apple.com', 'microsoft.com', 'twitter.com', 'instagram.com', 'linkedin.com',
#             'youtube.com', 'yahoo.com', 'ebay.com', 'github.com', 'stackoverflow.com',
#             'flipkart.com', 'paytm.com', 'phonepe.com', 'icicibank.com', 'hdfcbank.com',
#             'sbi.co.in', 'axisbank.com', 'kotak.com', 'swiggy.com', 'zomato.com',
#             'myntra.com', 'snapdeal.com', 'nykaa.com', 'makemytrip.com', 'irctc.co.in'
#         ]
#         brand_names_check = ['google', 'facebook', 'amazon', 'paypal', 'netflix', 
#                             'apple', 'microsoft', 'flipkart', 'paytm', 'icici', 'hdfc',
#                             'sbi', 'axis', 'kotak', 'swiggy', 'zomato']
#         brand_in_url = any(b in url.lower() for b in brand_names_check)
#         features['brand_impersonation'] = int(brand_in_url and full_domain not in legitimate_domains)
        
#         # Feature 3: Typosquatting Detection
#         major_brands = ['google', 'facebook', 'amazon', 'paypal', 'netflix', 'flipkart',
#                        'microsoft', 'apple', 'twitter', 'instagram', 'youtube']
#         max_similarity = 0
#         for brand in major_brands:
#             similarity = SequenceMatcher(None, domain.lower(), brand).ratio()
#             max_similarity = max(max_similarity, similarity)
        
#         features['typosquatting_similarity'] = max_similarity
#         features['is_typosquatting'] = int(0.75 < max_similarity < 0.95)  # Similar but not exact
        
#         # Feature 4: Suspicious TLD + Brand Combination
#         suspicious_tlds_list = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'club', 'buzz', 'loan']
#         features['suspicious_tld_brand_combo'] = int(suffix.lower() in suspicious_tlds_list and brand_in_url)

#     except Exception as e:
#         print(f"⚠️  Error processing URL: {url[:50] if isinstance(url, str) else 'Invalid'}... - {str(e)}")
#         # Return default features with 0 values
#         features = {
#             'url_length': 0, 'num_dots': 0, 'num_hyphens': 0, 'num_underscores': 0,
#             'num_digits': 0, 'num_letters': 0, 'num_special_chars': 0, 'has_ip': 0,
#             'num_subdomains': 0, 'has_multiple_subdomains': 0, 'domain_length': 0,
#             'host_entropy': 0, 'domain_entropy': 0, 'domain_has_digits': 0,
#             'domain_digit_ratio': 0, 'domain_vowel_ratio': 0, 'domain_bigram_diversity': 0,
#             'domain_trigram_diversity': 0, 'suspicious_prefix_suffix': 0,
#             'num_suspicious_symbols': 0, 'subdomain_length': 0, 'domain_is_dictionary_word': 0,
#             'tld_length': 0, 'tld_trust_category': 0, 'is_suspicious_tld': 0,
#             'is_high_trust_tld': 0, 'is_country_tld': 0, 'path_length': 0,
#             'num_path_segments': 0, 'num_query_params': 0, 'query_length': 0,
#             'num_encoded_chars': 0, 'num_fragments': 0, 'path_entropy': 0,
#             'path_has_suspicious_ext': 0, 'query_has_redirect': 0, 'path_url_ratio': 0,
#             'suspicious_word': 0, 'num_suspicious_words': 0, 'sensitive_word': 0,
#             'action_word': 0, 'has_brand_name': 0, 'brand_not_in_domain': 0,
#             'is_shortening_service': 0, 'is_mixed_case': 0, 'num_repeated_chars': 0,
#             'longest_token_length': 0, 'digit_letter_ratio': 0, 'special_char_ratio': 0,
#             'uppercase_ratio': 0, 'consecutive_consonants': 0, 'url_entropy': 0,
#             'has_port': 0, 'uses_https': 0, 'punycode_domain': 0, 'subdomain_count_dot': 0,
#             'domain_url_ratio': 0, 'query_url_ratio': 0,
#             # New features defaults
#             'brand_with_hyphen': 0, 'brand_impersonation': 0,
#             'typosquatting_similarity': 0, 'is_typosquatting': 0,
#             'suspicious_tld_brand_combo': 0
#         }

#     return features


# def batch_extract_features(urls, progress_interval=5000):
#     """
#     Extract features for a batch of URLs with progress tracking
    
#     Args:
#         urls: List or Series of URLs
#         progress_interval: Print progress every N URLs
    
#     Returns:
#         DataFrame with extracted features
#     """
#     features_list = []
#     total = len(urls)

#     for idx, url in enumerate(urls):
#         if idx % progress_interval == 0 and idx > 0:
#             progress = (idx / total) * 100
#             print(f"  ⏳ Processed {idx:,}/{total:,} URLs ({progress:.1f}%)")

#         features_list.append(extract_features_enhanced(url))

#     return pd.DataFrame(features_list)

# Better brand personiation problem solved

"""
Script 2: Feature extraction utility functions (FIXED VERSION)
Contains all helper functions and feature extraction logic
Import this in other scripts to extract features

FIXES:
1. Brand impersonation now checks DOMAIN only, not entire URL
2. Improved typosquatting detection (catches google-login, secure-paypal, etc.)
3. Better brand-with-hyphen detection (bidirectional)
4. Added character substitution detection (g00gle, faceb00k)
5. Multiple brands in domain detection
6. Legitimate domain whitelist expanded
"""

# import pandas as pd
# import numpy as np
# import re
# from urllib.parse import urlparse
# from tldextract import extract
# import math
# from collections import Counter
# from difflib import SequenceMatcher

# # ============================================================
# # CONSTANTS - LEGITIMATE DOMAINS & BRANDS
# # ============================================================

# # Comprehensive list of legitimate brand domains (with common variations)
# LEGITIMATE_BRAND_DOMAINS = {
#     # Google ecosystem
#     'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de',
#     'google.fr', 'google.com.au', 'google.co.jp', 'google.com.br',
#     'gmail.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com',
#     'google-analytics.com', 'googlevideo.com', 'googletagmanager.com',
    
#     # Facebook/Meta ecosystem
#     'facebook.com', 'fb.com', 'fbcdn.net', 'facebook.net',
#     'instagram.com', 'cdninstagram.com',
#     'whatsapp.com', 'whatsapp.net',
    
#     # Amazon ecosystem
#     'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
#     'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazon.com.br',
#     'amazonws.com', 'amazonaws.com', 'cloudfront.net', 'awsstatic.com',
    
#     # Microsoft ecosystem
#     'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com',
#     'microsoft.net', 'microsoftonline.com', 'azure.com', 'visualstudio.com',
    
#     # Apple ecosystem
#     'apple.com', 'icloud.com', 'apple.co', 'me.com', 'mac.com',
    
#     # PayPal
#     'paypal.com', 'paypal.me', 'paypalobjects.com',
    
#     # Netflix
#     'netflix.com', 'nflxext.com', 'nflxvideo.net', 'nflximg.net',
    
#     # Social Media
#     'twitter.com', 't.co', 'twimg.com',
#     'linkedin.com', 'licdn.com',
#     'youtube.com', 'youtu.be', 'ytimg.com', 'youtube-nocookie.com',
#     'reddit.com', 'redd.it', 'redditmedia.com',
#     'tiktok.com', 'tiktokcdn.com',
#     'pinterest.com', 'pinimg.com',
#     'snapchat.com',
    
#     # Indian E-commerce & Services
#     'flipkart.com', 'flipkart.net',
#     'paytm.com', 'paytmbank.com',
#     'phonepe.com',
#     'myntra.com',
#     'snapdeal.com',
#     'nykaa.com',
#     'meesho.com',
#     'ajio.com',
    
#     # Indian Banks
#     'icicibank.com', 'icicibank.co.in',
#     'hdfcbank.com', 'hdfcbank.co.in',
#     'sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi',
#     'axisbank.com', 'axisbank.co.in',
#     'kotak.com', 'kotakbank.com',
#     'pnbindia.in',
#     'canarabank.in',
#     'bankofbaroda.in',
#     'unionbankofindia.co.in',
#     'idbi.com',
    
#     # Indian Services
#     'swiggy.com', 'swiggy.in',
#     'zomato.com',
#     'ola.cab', 'olacabs.com',
#     'uber.com',
#     'makemytrip.com',
#     'goibibo.com',
#     'irctc.co.in', 'irctc.com',
#     'uidai.gov.in',
#     'epfindia.gov.in',
    
#     # US Banks & Finance
#     'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
#     'usbank.com', 'capitalone.com',
    
#     # Other Major Sites
#     'ebay.com', 'etsy.com',
#     'yahoo.com', 'yimg.com',
#     'github.com', 'githubusercontent.com',
#     'stackoverflow.com', 'stackexchange.com',
#     'medium.com',
#     'wordpress.com', 'wordpress.org',
#     'shopify.com',
#     'adobe.com',
#     'salesforce.com',
#     'spotify.com', 'scdn.co',
#     'zoom.us',
#     'dropbox.com',
#     'wikipedia.org', 'wikimedia.org',
    
#     # Delivery & Logistics
#     'dhl.com', 'fedex.com', 'ups.com', 'usps.com',
# }

# # Brand keywords to check (lowercase)
# BRAND_KEYWORDS = [
#     'google', 'gmail', 'facebook', 'instagram', 'whatsapp', 'amazon', 
#     'microsoft', 'apple', 'icloud', 'paypal', 'netflix', 'twitter', 
#     'linkedin', 'youtube', 'reddit', 'tiktok', 'pinterest', 'snapchat',
#     'flipkart', 'paytm', 'phonepe', 'myntra', 'snapdeal', 'nykaa', 'meesho',
#     'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'pnb', 'canara', 'bob',
#     'swiggy', 'zomato', 'ola', 'uber', 'makemytrip', 'goibibo', 'irctc',
#     'ebay', 'etsy', 'yahoo', 'github', 'stackoverflow', 'medium', 'wordpress',
#     'shopify', 'adobe', 'salesforce', 'spotify', 'zoom', 'dropbox', 'wikipedia',
#     'chase', 'wellsfargo', 'citibank', 'bankofamerica',
#     'dhl', 'fedex', 'ups', 'usps'
# ]

# # ============================================================
# # HELPER FUNCTIONS
# # ============================================================

# def shannon_entropy(s):
#     """Calculate Shannon entropy of a string"""
#     if not isinstance(s, str) or len(s) == 0:
#         return 0
#     s = ''.join(c for c in s if 32 <= ord(c) <= 126)
#     if len(s) == 0:
#         return 0
#     prob = [float(s.count(c)) / len(s) for c in set(s)]
#     return -sum([p * math.log2(p) for p in prob if p > 0])

# def longest_repeated_char(s):
#     """Find longest sequence of repeated characters"""
#     if not s:
#         return 0
#     max_count = count = 1
#     for i in range(1, len(s)):
#         if s[i] == s[i - 1]:
#             count += 1
#             max_count = max(max_count, count)
#         else:
#             count = 1
#     return max_count

# def vowel_consonant_ratio(s):
#     """Calculate ratio of vowels to consonants"""
#     vowels = sum(1 for c in s.lower() if c in 'aeiou')
#     consonants = sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')
#     return vowels / consonants if consonants > 0 else 0

# def get_tld_category(tld):
#     """Categorize TLD by trust level"""
#     high_trust_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in']
#     suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'buzz', 'loan']

#     if tld in high_trust_tlds:
#         return 2  # High trust
#     elif tld in suspicious_tlds:
#         return 0  # Suspicious
#     else:
#         return 1  # Neutral

# def count_ngrams(s, n=2):
#     """Count character n-grams (useful for detecting randomness)"""
#     if len(s) < n:
#         return 0
#     ngrams = [s[i:i + n] for i in range(len(s) - n + 1)]
#     counter = Counter(ngrams)
#     return len(counter)

# def safe_max_len_list(values):
#     """Safely get max from list of lengths"""
#     try:
#         return max(values) if values else 0
#     except ValueError:
#         return 0

# def safe_max_match_length(pattern, text):
#     """Safely compute max regex match length"""
#     try:
#         matches = [len(m.group()) for m in re.finditer(pattern, text)]
#         return max(matches) if matches else 0
#     except Exception:
#         return 0

# def has_character_substitution(text):
#     """
#     Detect common character substitutions used in phishing (leetspeak)
#     Examples: g00gle (o→0), faceb00k, paypa1 (l→1), micr0soft
#     """
#     substitutions = {
#         'o': '0', 'O': '0',
#         'i': '1', 'I': '1', 'l': '1', 'L': '1',
#         'e': '3', 'E': '3',
#         'a': '@', 'A': '@',
#         's': '$', 'S': '$',
#         'g': '9', 'G': '9',
#         't': '7', 'T': '7'
#     }
    
#     text_lower = text.lower()
#     for original, replacement in substitutions.items():
#         if replacement in text:
#             # Check if this looks like substitution (not just coincidence)
#             # e.g., "g00gle" has '0' but no 'o'
#             for brand in BRAND_KEYWORDS:
#                 if original.lower() in brand:
#                     # Create expected substitution pattern
#                     pattern = brand.replace(original.lower(), replacement)
#                     if pattern in text_lower:
#                         return True
#     return False

# def check_advanced_typosquatting(domain, brand_list):
#     """
#     Advanced typosquatting detection
#     Catches:
#     - Character substitution (g00gle)
#     - Brand as substring with extras (google-login, secure-google)
#     - High similarity (gogle, googl)
#     - Homograph attacks
    
#     Returns: (is_typo, similarity_score, matched_brand)
#     """
#     domain_clean = domain.lower().replace('-', '').replace('_', '').replace('.', '')
    
#     max_similarity = 0.0
#     matched_brand = None
#     is_typosquatting = False
    
#     for brand in brand_list:
#         # Case 1: Exact match (NOT typosquatting)
#         if domain_clean == brand:
#             return False, 1.0, brand
        
#         # Case 2: Brand is substring with additions (google-login → googlelogin)
#         if brand in domain_clean and len(domain_clean) > len(brand):
#             # This is suspicious unless it's a known legitimate domain
#             is_typosquatting = True
#             max_similarity = 0.85  # High but not exact
#             matched_brand = brand
#             continue
        
#         # Case 3: High string similarity (gogle, googl, goolge)
#         similarity = SequenceMatcher(None, domain_clean, brand).ratio()
#         if similarity > max_similarity:
#             max_similarity = similarity
#             matched_brand = brand
        
#         # If similarity is high but not exact, it's typosquatting
#         if 0.7 <= similarity < 1.0:
#             is_typosquatting = True
        
#         # Case 4: Check character substitution patterns
#         if has_character_substitution(domain):
#             # Check if it matches this brand with substitutions
#             for original, replacement in [('o', '0'), ('i', '1'), ('l', '1'), ('e', '3')]:
#                 pattern = brand.replace(original, replacement)
#                 if pattern in domain_clean:
#                     is_typosquatting = True
#                     max_similarity = 0.8
#                     matched_brand = brand
#                     break
    
#     return is_typosquatting, max_similarity, matched_brand

# # ============================================================
# # MAIN FEATURE EXTRACTION
# # ============================================================

# def extract_features_enhanced(url):
#     """
#     Extract comprehensive features from URL
    
#     Returns:
#         dict: Dictionary with 65+ feature values
#     """
#     features = {}

#     try:
#         if not isinstance(url, str) or len(url.strip()) == 0:
#             raise ValueError("Invalid or empty URL string")

#         # Remove non-printable/corrupt characters
#         url = ''.join(c for c in url if 32 <= ord(c) <= 126)

#         parsed = urlparse(url)
#         ext = extract(url)

#         domain = ext.domain
#         subdomain = ext.subdomain
#         suffix = ext.suffix  # TLD
#         path = parsed.path
#         query = parsed.query
#         netloc = parsed.netloc

#         # ========================================
#         # SECTION 1: BASIC STRUCTURAL (10 features)
#         # ========================================
#         features['url_length'] = len(url)
#         features['num_dots'] = url.count('.')
#         features['num_hyphens'] = url.count('-')
#         features['num_underscores'] = url.count('_')
#         features['num_digits'] = sum(c.isdigit() for c in url)
#         features['num_letters'] = sum(c.isalpha() for c in url)
#         features['num_special_chars'] = sum(url.count(c) for c in ['@', '?', '=', '%', '&', '!', '+', '$'])
#         features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', netloc)))
#         features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
#         features['has_multiple_subdomains'] = int(features['num_subdomains'] >= 3)

#         # ========================================
#         # SECTION 2: DOMAIN ANALYSIS (12 features)
#         # ========================================
#         features['domain_length'] = len(domain)
#         features['host_entropy'] = shannon_entropy(domain)
#         features['domain_entropy'] = shannon_entropy(domain)
#         features['domain_has_digits'] = int(any(c.isdigit() for c in domain))
#         features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
#         features['domain_vowel_ratio'] = vowel_consonant_ratio(domain)
#         features['domain_bigram_diversity'] = count_ngrams(domain, 2) / len(domain) if len(domain) >= 2 else 0
#         features['domain_trigram_diversity'] = count_ngrams(domain, 3) / len(domain) if len(domain) >= 3 else 0
#         features['suspicious_prefix_suffix'] = int('-' in domain or domain.startswith('www-') or domain.startswith('m-'))
#         features['num_suspicious_symbols'] = sum(domain.count(c) for c in ['@', '!', '*'])
#         features['subdomain_length'] = len(subdomain) if subdomain else 0
        
#         # Check if domain is a known legitimate word/brand
#         features['domain_is_dictionary_word'] = int(domain.lower() in BRAND_KEYWORDS)

#         # ========================================
#         # SECTION 3: TLD ANALYSIS (5 features)
#         # ========================================
#         features['tld_length'] = len(suffix)
#         features['tld_trust_category'] = get_tld_category(suffix.lower())
#         features['is_suspicious_tld'] = int(suffix.lower() in ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'info', 'biz', 'buzz', 'loan'])
#         features['is_high_trust_tld'] = int(suffix.lower() in ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in'])
#         features['is_country_tld'] = int(len(suffix) == 2 and suffix.isalpha())

#         # ========================================
#         # SECTION 4: PATH/QUERY ANALYSIS (10 features)
#         # ========================================
#         features['path_length'] = len(path)
#         features['num_path_segments'] = len([p for p in path.split('/') if p])
#         features['num_query_params'] = len(query.split('&')) if query else 0
#         features['query_length'] = len(query)
#         features['num_encoded_chars'] = url.count('%')
#         features['num_fragments'] = url.count('#')
#         features['path_entropy'] = shannon_entropy(path)
#         features['path_has_suspicious_ext'] = int(any(ext_name in path.lower() for ext_name in ['.exe', '.zip', '.apk', '.scr', '.bat', '.cmd']))
#         features['query_has_redirect'] = int(any(word in query.lower() for word in ['redirect', 'url=', 'next=', 'continue=', 'return=']))
#         features['path_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0

#         # ========================================
#         # SECTION 5: KEYWORD/LEXICAL (8 features)
#         # ========================================
#         suspicious_words = ['login', 'secure', 'update', 'account', 'verify', 'confirm', 'click', 'bank', 'paypal',
#                             'signin', 'password', 'urgent', 'suspended', 'locked', 'expire', 'reward', 'prize',
#                             'winner', 'claim', 'free', 'wallet', 'kyc', 'blocked', 'reactivate']
#         features['suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
#         features['num_suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
#         features['sensitive_word'] = int(any(word in url.lower() for word in ['bank', 'paypal', 'account', 'password', 'credit', 'card', 'wallet', 'upi']))
#         features['action_word'] = int(any(word in url.lower() for word in ['click', 'verify', 'confirm', 'update', 'download', 'install']))
        
#         # Check if brand name appears anywhere in URL
#         features['has_brand_name'] = int(any(brand in url.lower() for brand in BRAND_KEYWORDS))
        
#         # Brand appears in URL but NOT in the actual domain (red flag!)
#         brand_in_domain = any(brand in domain.lower() for brand in BRAND_KEYWORDS)
#         brand_in_url = any(brand in url.lower() for brand in BRAND_KEYWORDS)
#         features['brand_not_in_domain'] = int(brand_in_url and not brand_in_domain)
        
#         features['is_shortening_service'] = int(any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']))
#         features['is_mixed_case'] = int(any(c.isupper() for c in url) and any(c.islower() for c in url))

#         # ========================================
#         # SECTION 6: CHARACTER PATTERNS (6 features)
#         # ========================================
#         features['num_repeated_chars'] = longest_repeated_char(url)
#         features['longest_token_length'] = safe_max_len_list([len(t) for t in re.split(r'[./?=&_-]', url)]) if url else 0
#         features['digit_letter_ratio'] = features['num_digits'] / features['num_letters'] if features['num_letters'] > 0 else 0
#         features['special_char_ratio'] = features['num_special_chars'] / len(url) if len(url) > 0 else 0
#         features['uppercase_ratio'] = sum(1 for c in url if c.isupper()) / len(url) if len(url) > 0 else 0
#         features['consecutive_consonants'] = safe_max_match_length(r'[bcdfghjklmnpqrstvwxyz]+', url.lower()) if url else 0

#         # ========================================
#         # SECTION 7: ENTROPY MEASURES (1 feature)
#         # ========================================
#         features['url_entropy'] = shannon_entropy(url)

#         # ========================================
#         # SECTION 8: SECURITY INDICATORS (4 features)
#         # ========================================
#         features['has_port'] = int(':' in netloc and not netloc.startswith('['))
#         features['uses_https'] = int(parsed.scheme == 'https')
#         features['punycode_domain'] = int('xn--' in domain)
#         features['subdomain_count_dot'] = subdomain.count('.') if subdomain else 0

#         # ========================================
#         # SECTION 9: STRUCTURAL RATIOS (2 features)
#         # ========================================
#         features['domain_url_ratio'] = len(domain) / len(url) if len(url) > 0 else 0
#         features['query_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0

#         # ========================================
#         # SECTION 10: BRAND IMPERSONATION FEATURES (FIXED) - 9 features
#         # ========================================
        
#         # Construct full domain (domain + TLD)
#         full_domain = f"{domain}.{suffix}".lower() if suffix else domain.lower()
        
#         # Feature 1: Is this domain exactly a known legitimate domain?
#         is_legitimate = full_domain in LEGITIMATE_BRAND_DOMAINS
        
#         # Feature 2: Does domain contain a brand keyword? (CHECK DOMAIN ONLY!)
#         brand_in_domain_check = any(brand in domain.lower() for brand in BRAND_KEYWORDS)
        
#         # Feature 3: CRITICAL - Brand Impersonation
#         # Brand present in domain BUT domain is NOT legitimate
#         features['brand_impersonation'] = int(brand_in_domain_check and not is_legitimate)
        
#         # Feature 4: Brand with hyphen (bidirectional check)
#         # Catches: google-login, secure-google, paypal-verify, login-paypal
#         has_hyphen = '-' in domain
#         features['brand_with_hyphen'] = int(brand_in_domain_check and has_hyphen and not is_legitimate)
        
#         # Feature 5: Advanced Typosquatting Detection
#         is_typo, similarity, matched_brand = check_advanced_typosquatting(domain, BRAND_KEYWORDS)
#         features['is_typosquatting'] = int(is_typo)
#         features['typosquatting_similarity'] = similarity
        
#         # Feature 6: Character Substitution (leetspeak)
#         # Catches: g00gle, faceb00k, paypa1, micr0soft
#         features['has_character_substitution'] = int(has_character_substitution(domain))
        
#         # Feature 7: Suspicious TLD + Brand Combination
#         suspicious_tlds_list = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'club', 'buzz', 'loan', 'work', 'click']
#         features['suspicious_tld_brand_combo'] = int(suffix.lower() in suspicious_tlds_list and brand_in_domain_check and not is_legitimate)
        
#         # Feature 8: Multiple Brands in Domain (very suspicious!)
#         # Example: google-facebook-login.tk
#         brand_count = sum(1 for brand in BRAND_KEYWORDS if brand in domain.lower())
#         features['multiple_brands_in_domain'] = int(brand_count >= 2)
        
#         # Feature 9: Brand not in main domain (appears in subdomain/path instead)
#         # Example: google.malicious.com or malicious.com/google
#         features['brand_not_in_main_domain'] = int(brand_in_url and not brand_in_domain_check)

#     except Exception as e:
#         print(f"⚠️  Error processing URL: {url[:50] if isinstance(url, str) else 'Invalid'}... - {str(e)}")
#         # Return default features with 0 values
#         features = {
#             # Section 1
#             'url_length': 0, 'num_dots': 0, 'num_hyphens': 0, 'num_underscores': 0,
#             'num_digits': 0, 'num_letters': 0, 'num_special_chars': 0, 'has_ip': 0,
#             'num_subdomains': 0, 'has_multiple_subdomains': 0,
#             # Section 2
#             'domain_length': 0, 'host_entropy': 0, 'domain_entropy': 0, 'domain_has_digits': 0,
#             'domain_digit_ratio': 0, 'domain_vowel_ratio': 0, 'domain_bigram_diversity': 0,
#             'domain_trigram_diversity': 0, 'suspicious_prefix_suffix': 0,
#             'num_suspicious_symbols': 0, 'subdomain_length': 0, 'domain_is_dictionary_word': 0,
#             # Section 3
#             'tld_length': 0, 'tld_trust_category': 0, 'is_suspicious_tld': 0,
#             'is_high_trust_tld': 0, 'is_country_tld': 0,
#             # Section 4
#             'path_length': 0, 'num_path_segments': 0, 'num_query_params': 0, 'query_length': 0,
#             'num_encoded_chars': 0, 'num_fragments': 0, 'path_entropy': 0,
#             'path_has_suspicious_ext': 0, 'query_has_redirect': 0, 'path_url_ratio': 0,
#             # Section 5
#             'suspicious_word': 0, 'num_suspicious_words': 0, 'sensitive_word': 0,
#             'action_word': 0, 'has_brand_name': 0, 'brand_not_in_domain': 0,
#             'is_shortening_service': 0, 'is_mixed_case': 0,
#             # Section 6
#             'num_repeated_chars': 0, 'longest_token_length': 0, 'digit_letter_ratio': 0,
#             'special_char_ratio': 0, 'uppercase_ratio': 0, 'consecutive_consonants': 0,
#             # Section 7
#             'url_entropy': 0,
#             # Section 8
#             'has_port': 0, 'uses_https': 0, 'punycode_domain': 0, 'subdomain_count_dot': 0,
#             # Section 9
#             'domain_url_ratio': 0, 'query_url_ratio': 0,
#             # Section 10 (FIXED)
#             'brand_impersonation': 0, 'brand_with_hyphen': 0,
#             'is_typosquatting': 0, 'typosquatting_similarity': 0,
#             'has_character_substitution': 0, 'suspicious_tld_brand_combo': 0,
#             'multiple_brands_in_domain': 0, 'brand_not_in_main_domain': 0
#         }

#     return features


# def batch_extract_features(urls, progress_interval=5000):
#     """
#     Extract features for a batch of URLs with progress tracking
    
#     Args:
#         urls: List or Series of URLs
#         progress_interval: Print progress every N URLs
    
#     Returns:
#         DataFrame with extracted features
#     """
#     features_list = []
#     total = len(urls)

#     for idx, url in enumerate(urls):
#         if idx % progress_interval == 0 and idx > 0:
#             progress = (idx / total) * 100
#             print(f"  ⏳ Processed {idx:,}/{total:,} URLs ({progress:.1f}%)")

#         features_list.append(extract_features_enhanced(url))

#     return pd.DataFrame(features_list)


# # ============================================================
# # TESTING FUNCTION (for validation)
# # ============================================================

# def test_features():
#     """
#     Test feature extraction on critical cases
#     Run this to verify features are working correctly
#     """
#     test_cases = [
#         # Legitimate domains
#         ("https://www.google.com", "benign"),
#         ("https://www.facebook.com", "benign"),
#         ("https://www.paypal.com", "benign"),
#         ("https://www.amazon.com", "benign"),
        
#         # Brand impersonation with hyphen
#         ("https://www.google-login.tk", "phishing"),
#         ("https://www.paypal-secure.ml", "phishing"),
#         ("https://secure-google.com", "phishing"),
#         ("https://amazon-verify.ga", "phishing"),
        
#         # Typosquatting
#         ("https://www.g00gle.com", "phishing"),
#         ("https://www.faceb00k.com", "phishing"),
#         ("https://www.paypa1.com", "phishing"),
#         ("https://www.amaz0n.com", "phishing"),
        
#         # Complex cases
#         ("https://www.google.com.secure-login.tk", "phishing"),
#         ("https://accounts.google.com", "benign"),  # Real subdomain

#         ("https://google.com",           # Should: is_legitimate=True, impersonation=False
#     "https://google-login.tk",      # Should: is_legitimate=False, impersonation=True
#     "https://paypal.com",           # Should: is_legitimate=True, impersonation=False
#     "https://paypal-secure.ml",     # Should: is_legitimate=False, impersonation=True
#     "https://g00gle.com",)
#     ]
    
    
#     print("="*70)
#     print("FEATURE EXTRACTION TEST")
#     print("="*70)
    
#     for url, expected_type in test_cases:
#         features = extract_features_enhanced(url)
        
#         print(f"\n{url}")
#         print(f"Expected: {expected_type}")
#         print(f"Key Features:")
#         print(f"  brand_impersonation:        {features['brand_impersonation']}")
#         print(f"  brand_with_hyphen:          {features['brand_with_hyphen']}")
#         print(f"  is_typosquatting:           {features['is_typosquatting']}")
#         print(f"  has_character_substitution: {features['has_character_substitution']}")
#         print(f"  suspicious_tld_brand_combo: {features['suspicious_tld_brand_combo']}")
#         print(f"  typosquatting_similarity:   {features['typosquatting_similarity']:.2f}")
        
#         # Validation
#         if expected_type == "phishing":
#             phishing_signals = (
#                 features['brand_impersonation'] +
#                 features['brand_with_hyphen'] +
#                 features['is_typosquatting'] +
#                 features['has_character_substitution'] +
#                 features['suspicious_tld_brand_combo']
#             )
#             status = "✓ PASS" if phishing_signals >= 1 else "✗ FAIL"
#             print(f"  Total phishing signals: {phishing_signals} {status}")
#         else:
#             benign_check = features['brand_impersonation'] == 0
#             status = "✓ PASS" if benign_check else "✗ FAIL"
#             print(f"  Benign check: {status}")
    
#     print("\n" + "="*70)
#     print("TEST COMPLETE")
#     print("="*70)


# if __name__ == "__main__":
#     # Run tests if script is executed directly
#     print("Running feature extraction tests...\n")
#     test_features()

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from tldextract import extract
import math
from collections import Counter
from difflib import SequenceMatcher

# ============================================================
# CONSTANTS - LEGITIMATE DOMAINS & BRANDS
# ============================================================

# Comprehensive list of legitimate brand domains (with common variations)
LEGITIMATE_BRAND_DOMAINS = {
    # Google ecosystem
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.de',
    'google.fr', 'google.com.au', 'google.co.jp', 'google.com.br',
    'gmail.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com',
    'google-analytics.com', 'googlevideo.com', 'googletagmanager.com',

    # Facebook/Meta ecosystem
    'facebook.com', 'fb.com', 'fbcdn.net', 'facebook.net',
    'instagram.com', 'cdninstagram.com',
    'whatsapp.com', 'whatsapp.net',

    # Amazon ecosystem
    'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
    'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazon.com.br',
    'amazonws.com', 'amazonaws.com', 'cloudfront.net', 'awsstatic.com',

    # Microsoft ecosystem
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com',
    'microsoft.net', 'microsoftonline.com', 'azure.com', 'visualstudio.com',

    # Apple ecosystem
    'apple.com', 'icloud.com', 'apple.co', 'me.com', 'mac.com',

    # PayPal
    'paypal.com', 'paypal.me', 'paypalobjects.com',

    # Netflix
    'netflix.com', 'nflxext.com', 'nflxvideo.net', 'nflximg.net',

    # Social Media
    'twitter.com', 't.co', 'twimg.com',
    'linkedin.com', 'licdn.com',
    'youtube.com', 'youtu.be', 'ytimg.com', 'youtube-nocookie.com',
    'reddit.com', 'redd.it', 'redditmedia.com',
    'tiktok.com', 'tiktokcdn.com',
    'pinterest.com', 'pinimg.com',
    'snapchat.com',

    # Indian E-commerce & Services
    'flipkart.com', 'flipkart.net',
    'paytm.com', 'paytmbank.com',
    'phonepe.com',
    'myntra.com',
    'snapdeal.com',
    'nykaa.com',
    'meesho.com',
    'ajio.com',

    # Indian Banks
    'icicibank.com', 'icicibank.co.in',
    'hdfcbank.com', 'hdfcbank.co.in',
    'sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi',
    'axisbank.com', 'axisbank.co.in',
    'kotak.com', 'kotakbank.com',
    'pnbindia.in',
    'canarabank.in',
    'bankofbaroda.in',
    'unionbankofindia.co.in',
    'idbi.com',

    # Indian Services
    'swiggy.com', 'swiggy.in',
    'zomato.com',
    'ola.cab', 'olacabs.com',
    'uber.com',
    'makemytrip.com',
    'goibibo.com',
    'irctc.co.in', 'irctc.com',
    'uidai.gov.in',
    'epfindia.gov.in',

    # US Banks & Finance
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'usbank.com', 'capitalone.com',

    # Other Major Sites
    'ebay.com', 'etsy.com',
    'yahoo.com', 'yimg.com',
    'github.com', 'githubusercontent.com',
    'stackoverflow.com', 'stackexchange.com',
    'medium.com',
    'wordpress.com', 'wordpress.org',
    'shopify.com',
    'adobe.com',
    'salesforce.com',
    'spotify.com', 'scdn.co',
    'zoom.us',
    'dropbox.com',
    'wikipedia.org', 'wikimedia.org',

    # Delivery & Logistics
    'dhl.com', 'fedex.com', 'ups.com', 'usps.com',
}

# Brand keywords to check (lowercase)
BRAND_KEYWORDS = [
    'google', 'gmail', 'facebook', 'instagram', 'whatsapp', 'amazon',
    'microsoft', 'apple', 'icloud', 'paypal', 'netflix', 'twitter',
    'linkedin', 'youtube', 'reddit', 'tiktok', 'pinterest', 'snapchat',
    'flipkart', 'paytm', 'phonepe', 'myntra', 'snapdeal', 'nykaa', 'meesho',
    'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'pnb', 'canara', 'bob',
    'swiggy', 'zomato', 'ola', 'uber', 'makemytrip', 'goibibo', 'irctc',
    'ebay', 'etsy', 'yahoo', 'github', 'stackoverflow', 'medium', 'wordpress',
    'shopify', 'adobe', 'salesforce', 'spotify', 'zoom', 'dropbox', 'wikipedia',
    'chase', 'wellsfargo', 'citibank', 'bankofamerica',
    'dhl', 'fedex', 'ups', 'usps'
]

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def shannon_entropy(s):
    if not isinstance(s, str) or len(s) == 0:
        return 0
    s = ''.join(c for c in s if 32 <= ord(c) <= 126)
    if len(s) == 0:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob if p > 0])

def longest_repeated_char(s):
    if not s:
        return 0
    max_count = count = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
    return max_count

def vowel_consonant_ratio(s):
    vowels = sum(1 for c in s.lower() if c in 'aeiou')
    consonants = sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')
    return vowels / consonants if consonants > 0 else 0

def get_tld_category(tld):
    high_trust_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in']
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'buzz', 'loan']
    if tld in high_trust_tlds:
        return 2
    elif tld in suspicious_tlds:
        return 0
    else:
        return 1

def count_ngrams(s, n=2):
    if len(s) < n:
        return 0
    ngrams = [s[i:i + n] for i in range(len(s) - n + 1)]
    counter = Counter(ngrams)
    return len(counter)

def safe_max_len_list(values):
    try:
        return max(values) if values else 0
    except ValueError:
        return 0

def safe_max_match_length(pattern, text):
    try:
        matches = [len(m.group()) for m in re.finditer(pattern, text)]
        return max(matches) if matches else 0
    except Exception:
        return 0

def has_character_substitution(text):
    substitutions = {
        'o': '0', 'O': '0',
        'i': '1', 'I': '1', 'l': '1', 'L': '1',
        'e': '3', 'E': '3',
        'a': '@', 'A': '@',
        's': '$', 'S': '$',
        'g': '9', 'G': '9',
        't': '7', 'T': '7'
    }
    text_lower = text.lower()
    for original, replacement in substitutions.items():
        if replacement in text:
            for brand in BRAND_KEYWORDS:
                if original.lower() in brand:
                    pattern = brand.replace(original.lower(), replacement)
                    if pattern in text_lower:
                        return True
    return False

def check_advanced_typosquatting(domain, brand_list):
    domain_clean = domain.lower().replace('-', '').replace('_', '').replace('.', '')
    max_similarity = 0.0
    matched_brand = None
    is_typosquatting = False
    for brand in brand_list:
        if domain_clean == brand:
            return False, 1.0, brand
        if brand in domain_clean and len(domain_clean) > len(brand):
            is_typosquatting = True
            max_similarity = 0.85
            matched_brand = brand
            continue
        similarity = SequenceMatcher(None, domain_clean, brand).ratio()
        if similarity > max_similarity:
            max_similarity = similarity
            matched_brand = brand
        if 0.7 <= similarity < 1.0:
            is_typosquatting = True
        if has_character_substitution(domain):
            for original, replacement in [('o', '0'), ('i', '1'), ('l', '1'), ('e', '3')]:
                pattern = brand.replace(original, replacement)
                if pattern in domain_clean:
                    is_typosquatting = True
                    max_similarity = 0.8
                    matched_brand = brand
                    break
    return is_typosquatting, max_similarity, matched_brand

# ============================================================
# FIX FUNCTION FOR CHARACTER SUBSTITUTION DETECTION
# ============================================================

def matches_brand_with_substitution(domain_text, brand_list):
    domain_lower = domain_text.lower()
    for brand in brand_list:
        if brand in domain_lower:
            return True, brand
    substitution_map = {
        'o': ['0'],
        'i': ['1'],
        'l': ['1'],
        'e': ['3'],
        'a': ['@'],
        's': ['$'],
        'g': ['9'],
        't': ['7']
    }
    for brand in brand_list:
        variations = [brand]
        for original_char, replacements in substitution_map.items():
            if original_char in brand:
                new_variations = []
                for variant in variations:
                    for replacement in replacements:
                        new_variant = variant.replace(original_char, replacement)
                        new_variations.append(new_variant)
                variations.extend(new_variations)
        for variant in set(variations):
            if variant in domain_lower and variant != brand:
                return True, brand
    return False, None

# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features_enhanced(url):
    features = {}
    try:
        if not isinstance(url, str) or len(url.strip()) == 0:
            raise ValueError("Invalid or empty URL string")

        url = ''.join(c for c in url if 32 <= ord(c) <= 126)
        parsed = urlparse(url)
        ext = extract(url)
        domain = ext.domain
        subdomain = ext.subdomain
        suffix = ext.suffix
        path = parsed.path
        query = parsed.query
        netloc = parsed.netloc

        # SECTION 1–9 (unchanged)
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['num_special_chars'] = sum(url.count(c) for c in ['@', '?', '=', '%', '&', '!', '+', '$'])
        features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', netloc)))
        features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
        features['has_multiple_subdomains'] = int(features['num_subdomains'] >= 3)

        features['domain_length'] = len(domain)
        features['host_entropy'] = shannon_entropy(domain)
        features['domain_entropy'] = shannon_entropy(domain)
        features['domain_has_digits'] = int(any(c.isdigit() for c in domain))
        features['domain_digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
        features['domain_vowel_ratio'] = vowel_consonant_ratio(domain)
        features['domain_bigram_diversity'] = count_ngrams(domain, 2) / len(domain) if len(domain) >= 2 else 0
        features['domain_trigram_diversity'] = count_ngrams(domain, 3) / len(domain) if len(domain) >= 3 else 0
        features['suspicious_prefix_suffix'] = int('-' in domain or domain.startswith('www-') or domain.startswith('m-'))
        features['num_suspicious_symbols'] = sum(domain.count(c) for c in ['@', '!', '*'])
        features['subdomain_length'] = len(subdomain) if subdomain else 0
        features['domain_is_dictionary_word'] = int(domain.lower() in BRAND_KEYWORDS)

        features['tld_length'] = len(suffix)
        features['tld_trust_category'] = get_tld_category(suffix.lower())
        features['is_suspicious_tld'] = int(suffix.lower() in ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'xyz', 'club', 'work', 'info', 'biz', 'buzz', 'loan'])
        features['is_high_trust_tld'] = int(suffix.lower() in ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co.in', 'ac.in', 'gov.in'])
        features['is_country_tld'] = int(len(suffix) == 2 and suffix.isalpha())

        features['path_length'] = len(path)
        features['num_path_segments'] = len([p for p in path.split('/') if p])
        features['num_query_params'] = len(query.split('&')) if query else 0
        features['query_length'] = len(query)
        features['num_encoded_chars'] = url.count('%')
        features['num_fragments'] = url.count('#')
        features['path_entropy'] = shannon_entropy(path)
        features['path_has_suspicious_ext'] = int(any(ext_name in path.lower() for ext_name in ['.exe', '.zip', '.apk', '.scr', '.bat', '.cmd']))
        features['query_has_redirect'] = int(any(word in query.lower() for word in ['redirect', 'url=', 'next=', 'continue=', 'return=']))
        features['path_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0

        suspicious_words = ['login', 'secure', 'update', 'account', 'verify', 'confirm', 'click', 'bank', 'paypal',
                            'signin', 'password', 'urgent', 'suspended', 'locked', 'expire', 'reward', 'prize',
                            'winner', 'claim', 'free', 'wallet', 'kyc', 'blocked', 'reactivate']
        features['suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
        features['num_suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
        features['sensitive_word'] = int(any(word in url.lower() for word in ['bank', 'paypal', 'account', 'password', 'credit', 'card', 'wallet', 'upi']))
        features['action_word'] = int(any(word in url.lower() for word in ['click', 'verify', 'confirm', 'update', 'download', 'install']))
        features['has_brand_name'] = int(any(brand in url.lower() for brand in BRAND_KEYWORDS))
        brand_in_domain = any(brand in domain.lower() for brand in BRAND_KEYWORDS)
        brand_in_url = any(brand in url.lower() for brand in BRAND_KEYWORDS)
        features['brand_not_in_domain'] = int(brand_in_url and not brand_in_domain)
        features['is_shortening_service'] = int(any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']))
        features['is_mixed_case'] = int(any(c.isupper() for c in url) and any(c.islower() for c in url))

        features['num_repeated_chars'] = longest_repeated_char(url)
        features['longest_token_length'] = safe_max_len_list([len(t) for t in re.split(r'[./?=&_-]', url)]) if url else 0
        features['digit_letter_ratio'] = features['num_digits'] / features['num_letters'] if features['num_letters'] > 0 else 0
        features['special_char_ratio'] = features['num_special_chars'] / len(url) if len(url) > 0 else 0
        features['uppercase_ratio'] = sum(1 for c in url if c.isupper()) / len(url) if len(url) > 0 else 0
        features['consecutive_consonants'] = safe_max_match_length(r'[bcdfghjklmnpqrstvwxyz]+', url.lower()) if url else 0
        features['url_entropy'] = shannon_entropy(url)

        features['has_port'] = int(':' in netloc and not netloc.startswith('['))
        features['uses_https'] = int(parsed.scheme == 'https')
        features['punycode_domain'] = int('xn--' in domain)
        features['subdomain_count_dot'] = subdomain.count('.') if subdomain else 0

        features['domain_url_ratio'] = len(domain) / len(url) if len(url) > 0 else 0
        features['query_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0

        # ========================================
        # SECTION 10: BRAND IMPERSONATION (FIXED)
        # ========================================
        full_domain = f"{domain}.{suffix}".lower() if suffix else domain.lower()
        is_legitimate = full_domain in LEGITIMATE_BRAND_DOMAINS
        brand_found, matched_brand = matches_brand_with_substitution(domain, BRAND_KEYWORDS)
        brand_in_domain_check = brand_found
        features['brand_impersonation'] = int(brand_in_domain_check and not is_legitimate)

        has_hyphen = '-' in domain
        features['brand_with_hyphen'] = int(brand_in_domain_check and has_hyphen and not is_legitimate)
        is_typo, similarity, matched_brand = check_advanced_typosquatting(domain, BRAND_KEYWORDS)
        features['is_typosquatting'] = int(is_typo)
        features['typosquatting_similarity'] = similarity
        features['has_character_substitution'] = int(has_character_substitution(domain))
        suspicious_tlds_list = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'xyz', 'club', 'buzz', 'loan', 'work', 'click']
        features['suspicious_tld_brand_combo'] = int(suffix.lower() in suspicious_tlds_list and brand_in_domain_check and not is_legitimate)
        brand_count = sum(1 for brand in BRAND_KEYWORDS if brand in domain.lower())
        features['multiple_brands_in_domain'] = int(brand_count >= 2)
        features['brand_not_in_main_domain'] = int(brand_in_url and not brand_in_domain_check)

    except Exception as e:
        print(f"⚠️  Error processing URL: {url[:50] if isinstance(url, str) else 'Invalid'}... - {str(e)}")

    return features

# ============================================================
# TEST FUNCTION
# ============================================================

def test_features():
    test_cases = [
        ("https://www.google.com", "benign"),
        ("https://www.g00gle.com", "phishing"),
        ("https://www.paypa1.com", "phishing"),
        ("https://www.faceb00k.com", "phishing"),
        ("https://google-login.tk", "phishing"),
        ("https://secure-google.com", "phishing"),
        ("https://accounts.google.com", "benign"),
    ]

    print("="*70)
    print("FEATURE EXTRACTION TEST")
    print("="*70)

    for url, expected_type in test_cases:
        f = extract_features_enhanced(url)
        print(f"\n{url}")
        print(f"Expected: {expected_type}")
        print(f"brand_impersonation: {f.get('brand_impersonation')}")
        print(f"has_character_substitution: {f.get('has_character_substitution')}")
        print(f"is_typosquatting: {f.get('is_typosquatting')}")
        print(f"typosquatting_similarity: {f.get('typosquatting_similarity')}")

    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)

def batch_extract_features(urls, progress_interval=5000):
    """
    Extract features for a batch of URLs with progress tracking.

    Args:
        urls (list or pd.Series): List of URLs.
        progress_interval (int): Show progress every N URLs.

    Returns:
        pd.DataFrame: Extracted features for all URLs.
    """
    features_list = []
    total = len(urls)

    for idx, url in enumerate(urls):
        if idx % progress_interval == 0 and idx > 0:
            progress = (idx / total) * 100
            print(f"⏳ Processed {idx:,}/{total:,} URLs ({progress:.1f}%)")

        features = extract_features_enhanced(url)
        features_list.append(features)

    return pd.DataFrame(features_list)

if __name__ == "__main__":
    test_features()
