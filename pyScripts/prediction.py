# PREDICTOIN ON BENIGN

import re, math, joblib, pandas as pd
from urllib.parse import urlparse, unquote
from tldextract import extract
from collections import Counter

# ---------- Helper ----------
def entropy(s):
    if not s or not isinstance(s, str):
        return 0
    s = ''.join(c for c in s if 32 <= ord(c) <= 126)
    if not s:
        return 0
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(pi * math.log2(pi) for pi in p if pi > 0)

def vowel_consonant_ratio(s):
    vowels = sum(1 for c in s.lower() if c in 'aeiou')
    consonants = sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')
    return vowels / consonants if consonants > 0 else 0

def count_ngrams(s, n=2):
    if len(s) < n: return 0
    ngrams = [s[i:i+n] for i in range(len(s)-n+1)]
    return len(set(ngrams))

def get_tld_category(tld):
    high_trust = ['com','org','net','edu','gov','mil','in','co.in','ac.in','gov.in']
    suspicious = ['tk','ml','ga','cf','gq','pw','cc','top','xyz','club','work','buzz','loan']
    if tld in high_trust: return 2
    if tld in suspicious: return 0
    return 1

def longest_repeated_char(s):
    if not s: return 0
    max_count = count = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
    return max_count


# ---------- Feature Extraction ----------
def extract_features(url):
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'http://' + url

    p = urlparse(url)
    ext = extract(url)
    domain, subdomain, suffix = ext.domain or '', ext.subdomain or '', ext.suffix or ''
    host, path, q = p.netloc.lower(), p.path, p.query
    full = unquote(url)

    features = {
        'url_length': len(full),
        'num_dots': full.count('.'),
        'num_hyphens': full.count('-'),
        'num_underscores': full.count('_'),
        'num_digits': sum(c.isdigit() for c in full),
        'num_letters': sum(c.isalpha() for c in full),
        'num_special_chars': sum(full.count(c) for c in ['@','?','=','%','&','!','+','$']),
        'has_ip': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', host))),
        'num_subdomains': len(subdomain.split('.')) if subdomain else 0,
        'has_multiple_subdomains': int(len(subdomain.split('.')) >= 3),
        'domain_length': len(domain),
        'host_entropy': entropy(domain),
        'domain_entropy': entropy(domain),
        'domain_has_digits': int(any(c.isdigit() for c in domain)),
        'domain_digit_ratio': sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0,
        'domain_vowel_ratio': vowel_consonant_ratio(domain),
        'domain_bigram_diversity': count_ngrams(domain, 2) / len(domain) if len(domain) >= 2 else 0,
        'domain_trigram_diversity': count_ngrams(domain, 3) / len(domain) if len(domain) >= 3 else 0,
        'suspicious_prefix_suffix': int('-' in domain or domain.startswith('www-') or domain.startswith('m-')),
        'num_suspicious_symbols': sum(domain.count(c) for c in ['@', '!', '*']),
        'subdomain_length': len(subdomain),
        'domain_is_dictionary_word': int(domain.lower() in ['google','facebook','amazon','apple','microsoft','wikipedia','paypal','youtube','twitter','linkedin','instagram','flipkart','zomato','swiggy','nykaa','icici','hdfc','sbi','axis']),
        'tld_length': len(suffix),
        'tld_trust_category': get_tld_category(suffix.lower()),
        'is_suspicious_tld': int(suffix.lower() in ['tk','ml','ga','cf','gq','pw','cc','top','xyz','club','work','buzz','loan']),
        'is_high_trust_tld': int(suffix.lower() in ['com','org','net','edu','gov','mil','in','co.in','ac.in','gov.in']),
        'is_country_tld': int(len(suffix) == 2 and suffix.isalpha()),
        'path_length': len(path),
        'num_path_segments': len([p for p in path.split('/') if p]),
        'num_query_params': len(q.split('&')) if q else 0,
        'query_length': len(q),
        'num_encoded_chars': full.count('%'),
        'num_fragments': full.count('#'),
        'path_entropy': entropy(path),
        'path_has_suspicious_ext': int(any(ext in path.lower() for ext in ['.exe','.zip','.apk','.scr','.bat','.cmd'])),
        'query_has_redirect': int(any(word in q.lower() for word in ['redirect','url=','next=','continue=','return='])),
        'path_url_ratio': len(path)/len(full) if len(full)>0 else 0,
        'suspicious_word': int(any(w in full.lower() for w in ['login','secure','update','account','verify','confirm','click','bank','paypal','signin','password','urgent','suspended','locked','expire','reward','prize','winner','claim','free','wallet','kyc','blocked','reactivate'])),
        'num_suspicious_words': sum(1 for w in ['login','secure','update','account','verify','confirm','click','bank','paypal','signin','password','urgent','suspended','locked','expire','reward','prize','winner','claim','free','wallet','kyc','blocked','reactivate'] if w in full.lower()),
        'sensitive_word': int(any(w in full.lower() for w in ['bank','paypal','account','password','credit','card','wallet','upi'])),
        'action_word': int(any(w in full.lower() for w in ['click','verify','confirm','update','download','install'])),
        'has_brand_name': int(any(b in full.lower() for b in ['google','facebook','amazon','microsoft','apple','paypal','netflix','instagram','twitter','linkedin','youtube','yahoo','ebay','icici','hdfc','sbi','axis','swiggy','zomato'])),
        'brand_not_in_domain': int(any(b in full.lower() for b in ['google','facebook','amazon','apple','paypal','youtube']) and not any(b in domain.lower() for b in ['google','facebook','amazon','apple','paypal','youtube'])),
        'is_shortening_service': int(any(s in full for s in ['bit.ly','tinyurl','goo.gl','t.co','ow.ly','is.gd','buff.ly'])),
        'is_mixed_case': int(any(c.isupper() for c in full) and any(c.islower() for c in full)),
        'num_repeated_chars': longest_repeated_char(full),
        'longest_token_length': max((len(t) for t in re.split(r'[./?=&_-]', full) if t), default=0),
        'digit_letter_ratio': sum(c.isdigit() for c in full) / sum(c.isalpha() for c in full) if sum(c.isalpha() for c in full) > 0 else 0,
        'special_char_ratio': sum(1 for c in full if not c.isalnum()) / len(full) if len(full) > 0 else 0,
        'uppercase_ratio': sum(1 for c in full if c.isupper()) / len(full) if len(full) > 0 else 0,
        'consecutive_consonants': max((len(m.group()) for m in re.finditer(r'[bcdfghjklmnpqrstvwxyz]+', full.lower())), default=0),
        'url_entropy': entropy(full),
        'has_port': int(':' in host and not host.startswith('[')),
        'uses_https': int(p.scheme == 'https'),
        'punycode_domain': int('xn--' in domain),
        'subdomain_count_dot': subdomain.count('.') if subdomain else 0,
        'domain_url_ratio': len(domain)/len(full) if len(full)>0 else 0,
        'query_url_ratio': len(q)/len(full) if len(full)>0 else 0
    }

    return pd.DataFrame([features])


# ---------- Load Model ----------
artifact = joblib.load('/content/drive/MyDrive/Webshield Dataset/LIGHTGBM Results 716k typosquatting /lgbm_url_classifier_v1.3.0.pkl')
model = artifact['model']
features = artifact['feature_names']

urls = [
    "https://www.gaeboy.com",
    "www.google.tk..https.com",
    "www.facebook.com",
    "www.youtube.com",
    "www.twitter.com",
    "www.instagram.com",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.netflix.com",
    "www.linkedin.com",
    "https://www.google.com",
    "https://www.facebook129.232.23.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.flipkart.com",
    "https://www.paytm.com",
    "https://www.icicibank.com",
    "https://www.hdfcbank.com",
    "https://www.swiggy.com",
    "https://www.zomato.com",
    "https://www.google-login.tk",
    "https://www.paypal-secure.ml",
    "https://www.amazon-verify.ga",
    "https://www.facebook-recovery.cf",
    "https://secure-netflix-account.xyz",
    "https://www.apple-id-locked.top",
    "https://www.paypal.com.verify-account.com",
    "https://www.amazon.com-login.net",
    "https://secure-google.com",
    "https://www.facebook-help.com",
    "https://www.goog1e.com",
    "https://www.faceb00k.com",
    "https://www.microoft.com",
    "https://www.arnazon.com",
    "https://login-google.com",
    "https://accounts-google-secure.test",
    "https://google-secure-login.test",
    "https://paypal-secure-login.test",
    "https://secure-paypal-update.test",
    "https://signin-amazon.test",
    "https://amazon-secure-update.test",
    "https://appleid-recovery.test",
    "https://appleid-security.test",
    "https://netflix-support.test",
    "https://facebook-account-secure.test",
    "https://linkedin-security.test",
    "https://github-login.test",
    "https://microsoft-account.verify.test",
    "https://support-google.com.scam",
    "https://google.payments.verify.test",
    "https://paypai.com",
    "https://amzon-payments.com",
    "https://face-book-login.org",
    "http://update-paypal.info",
    "http://secure-paypal-login.info",
    "https://verify-paytm.secure.test",
    "https://icici-bank-login.test",
    "https://hdfc-bank-verify.test",
    "https://swiggy-support-login.test",
    "https://zomato-account-verify.test",
    "https://accounts.google.security-alert.test",
    "https://apple-support-login.test",
    "https://microsoft-update-account.test",
    "https://paypal-account-recovery.test",
    "https://amazon-billing-alert.test",
    "https://netflix-payment-issue.test",
    "https://facebook-verify-now.test",
    "https://linkedin-verify-account.test",
    "https://github-2fa-setup.test",
    "https://stackoverflow-login.test",
    "https://reddit-security-alert.test",
    "https://flipkart-payment-verify.test",
    "https://paytm-verify-now.test",
    "https://secure-icicibank-login.test",
    "https://hdfc-verify-account.test",
    "https://delivery-swiggy.verify.test",
    "https://zomato-verify-payment.test",
    "https://www-google-login.example",
    "https://paypal-confirm.example",
    "https://amazon-secure.example",
    "https://facebook-restore.example",
    "https://netflix-verify.example",
    "https://apple-account.example",
    "https://google-support.example",
    "https://paypal-support.example",
    "https://amazon-support.example",
    "https://facebook-support.example",
    "https://netflix-support.example",
    "https://phish-google.test",
    "https://phish-paypal.test",
    "https://phish-amazon.test",
    "https://secure-login-google.co",
    "https://secure-login-paypal.co",
    "https://login-amazon-secure.co",
    "http://verify-google-login.org",
    "http://verify-paypal-login.org",
    "http://verify-amazon-login.org",
]


# ---------- Run Predictions ----------
results = []
for url in urls:
    X = extract_features(url)
    for col in features:
        if col not in X.columns:
            X[col] = 0
    X = X[features]
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    results.append({'URL': url, 'Predicted': pred, 'Probabilities': dict(zip(model.classes_, proba))})

df_results = pd.DataFrame(results)
print(df_results)
df_results.to_csv("famous_url_predictions.csv", index=False)
