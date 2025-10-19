import pandas as pd
import random

# Generate synthetic phishing URLs
def generate_phishing_urls(n=500):
    urls = []
    
    suspicious_domains = ['tk', 'ml', 'ga', 'cf', 'gq']
    phishing_keywords = ['verify', 'secure', 'account', 'update', 'confirm', 'login', 'signin']
    legitimate_sites = ['paypal', 'google', 'facebook', 'amazon', 'microsoft', 'apple']
    
    for _ in range(n):
        # Random phishing pattern
        pattern = random.choice([
            # Pattern 1: IP address
            f"http://{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}/{random.choice(phishing_keywords)}",
            
            # Pattern 2: Suspicious TLD
            f"http://{random.choice(legitimate_sites)}-{random.choice(phishing_keywords)}.{random.choice(suspicious_domains)}",
            
            # Pattern 3: Typosquatting
            f"http://{random.choice(legitimate_sites).replace('a', '4').replace('o', '0')}.com/{random.choice(phishing_keywords)}",
            
            # Pattern 4: Subdomain spam
            f"http://{random.choice(phishing_keywords)}.{random.choice(legitimate_sites)}.{random.choice(phishing_keywords)}.com",
            
            # Pattern 5: @ symbol trick
            f"http://legitimate.com@{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        ])
        
        urls.append(pattern)
    
    return urls

# Generate legitimate URLs
def generate_legitimate_urls(n=500):
    urls = []
    
    domains = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
        'wikipedia.org', 'reddit.com', 'github.com', 'stackoverflow.com',
        'linkedin.com', 'twitter.com', 'instagram.com', 'netflix.com',
        'apple.com', 'microsoft.com', 'adobe.com', 'medium.com'
    ]
    
    paths = ['', '/about', '/contact', '/products', '/services', '/blog', '/news']
    
    for _ in range(n):
        domain = random.choice(domains)
        path = random.choice(paths)
        protocol = 'https' if random.random() > 0.1 else 'http'
        
        urls.append(f"{protocol}://{domain}{path}")
    
    return urls

# Extract features
def extract_features(url):
    features = {}
    
    # Basic features
    features['url_length'] = len(url)
    features['domain_length'] = len(url.split('/')[2]) if len(url.split('/')) > 2 else 0
    features['path_length'] = len(url.split('/', 3)[-1]) if len(url.split('/')) > 3 else 0
    
    # Pattern features
    features['has_ip'] = 1 if any(char.isdigit() for char in url.split('/')[2]) and '.' in url.split('/')[2] else 0
    features['subdomain_count'] = url.split('/')[2].count('.') - 1 if len(url.split('/')) > 2 else 0
    features['has_at'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if url.count('//') > 1 else 0
    features['special_chars'] = sum(not c.isalnum() for c in url)
    features['is_https'] = 1 if url.startswith('https') else 0
    features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0
    features['has_suspicious_words'] = 1 if any(word in url.lower() for word in ['verify', 'secure', 'account', 'update', 'confirm']) else 0
    
    return features

# Create dataset
print("Generating dataset...")

phishing_urls = generate_phishing_urls(500)
legitimate_urls = generate_legitimate_urls(500)

data = []

for url in phishing_urls:
    features = extract_features(url)
    features['is_phishing'] = 1
    data.append(features)

for url in legitimate_urls:
    features = extract_features(url)
    features['is_phishing'] = 0
    data.append(features)

df = pd.DataFrame(data)

# Shuffle
df = df.sample(frac=1).reset_index(drop=0)

print(f"Dataset created: {len(df)} samples")
print(f"Phishing: {sum(df['is_phishing'])} | Legitimate: {len(df) - sum(df['is_phishing'])}")
print("\nFeatures:", df.columns.tolist())
print("\nFirst 5 rows:")
print(df.head())

df.to_csv('phishing_dataset.csv', index=False)
print("\n✅ Saved to phishing_dataset.csv")