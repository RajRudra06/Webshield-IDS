"""
Generate ~35,000 varied brand-impersonation phishing-like URLs.
Saves CSV: phishing_urls_35000.csv
"""

import random
import itertools
import csv
import string
from pathlib import Path

random.seed(42)

# -------------------------
# Config / pools
# -------------------------
TARGET = 35000
OUTFILE = Path("phishing_urls_35000.csv")

BRANDS = [
    # Existing global + Indian + popular services (kept)
    "google","facebook","amazon","apple","microsoft","youtube","twitter","instagram","linkedin","netflix",
    "paypal","ebay","spotify","dropbox","github","stackoverflow","reddit","walmart","target","nike",
    "adidas","samsung","intel","nvidia","tesla","uber","ola","airbnb","booking","expedia",
    "stripe","visa","mastercard","americanexpress","chase","boa","hsbc","citibank","wellsfargo",
    "flipkart","myntra","snapdeal","paytm","phonepe","googlepay","amazonpay","irctc","uidai","zomato",
    "swiggy","makemytrip","goibibo","nykaa","ajio","bigbasket","grofers",
    "mozilla","chrome","firefox","opera","adobe","oracle","aws","azure","gcp","docker",
    "slack","zoom","atlassian","jetbrains","discord","tiktok","pinterest","quora","medium","tumblr",
    # Added more well-known brands and services for higher variety
    "bing","yahoo","duckduckgo","protonmail","mailchimp","notion","trello","asana","calendly","canva",
    "stripe","square","intuit","freshbooks","xero","zendesk","okta","oneplus","xiaomi","huawei",
    "lenovo","asus","acer","hp","dell","lg","panasonic","sony","philips","seagate",
    "westernunion","moneygram","paypalme","soundcloud","vimeo","behance","dribbble","envato","etsy",
    "alibaba","aliexpress","mercadolibre","rakuten","indeed","glassdoor","monster","zillow","trulia",
    "tripadvisor","skyscanner","kayak","expedia","orbitz","rbs","svb","sofi","robinhood","coinbase",
    "binance","kraken","bitpay","ledger","trezor","epicgames","riotgames","ea","ubisoft","steam",
    "roblox","twitch","hulu","disneyplus","hbo","pbs","nationalgeographic","cnn","bbc","nytimes",
    "forbes","bloomberg","reuters","guardian","amazonprime","primevideo","sainsburys","tesco","ikea",
    "homedepot","lowes","sephora","ulta","costco","targetau","argos","currys"
]

# Patterns produce path/host style variants. Use placeholders {brand} and {typo}
PATTERNS = [
    "{brand}-login","{brand}-secure","{brand}-verify","{brand}-account","{brand}-recovery",
    "secure-{brand}","verify-{brand}","{brand}-help","{brand}-support","my-{brand}",
    "{brand}.com-login","www.{brand}.com-secure","{brand}-signin","{brand}-update","{brand}-auth",
    "login-{brand}","accounts-{brand}","{brand}-portal","{brand}-portal-login","{brand}-customer",
    "{brand}-payments","{brand}-billing","{brand}-checkout","{brand}-otp","{brand}-confirm",
    "{brand}-secure-login","{brand}-verify-account","{brand}-secure-update","{brand}-notice","{brand}-alert",
    "{brand}login","{brand}secure","{brand}verify","{brand}account","{brand}recovery"
]

TLDS = [
    ".com",".net",".org",".info",".biz",".co",".in",".co.in",".io",".cc",
    ".tk",".ml",".ga",".cf",".gq",".pw",".xyz",".top",".club",".online",
    ".site",".website",".space",".store",".tech",".app",".pro",".me",".shop"
]

SUBS = ["www","login","secure","accounts","safe","verify","portal","update","auth","support","help","customer"]

ACTIONS = ["login","verify","confirm","update","secure","auth","signin","continue","redirect","next","return"]

HOMO = {"o":"0","i":"1","l":"1","a":"@","e":"3","s":"5","t":"7","g":"9","b":"8","c":"("}

# -------------------------
# helper generators
# -------------------------
def typos_for(brand):
    """Generate multiple typo/variants for a brand"""
    variants = set()
    b = brand
    # simple substitutions/homoglyphs
    for i in range(len(b)):
        ch = b[i]
        if ch in HOMO:
            variants.add(b[:i] + HOMO[ch] + b[i+1:])
    # drop a character
    if len(b) > 3:
        for i in range(len(b)):
            variants.add(b[:i] + b[i+1:])
    # duplicate a char
    for i in range(len(b)):
        variants.add(b[:i] + b[i] + b[i:])
    # swap adjacent (transposition)
    for i in range(len(b)-1):
        variants.add(b[:i] + b[i+1] + b[i] + b[i+2:])
    # insert digits
    for d in ("1","12","123","2023"):
        variants.add(b + d)
        variants.add(d + b)
    # replace common digrams
    subs = [("rn","m"),("vv","w"),("cl","d"),("er","ar")]
    for old,new in subs:
        if old in b:
            variants.add(b.replace(old,new))
    return {v for v in variants if v and v != b}

def rand_token(n=4):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def random_path():
    parts = []
    depth = random.choices([0,1,2,3], weights=[0.4,0.35,0.2,0.05])[0]
    for _ in range(depth):
        parts.append(random.choice(["login","secure","account","user","update","id", rand_token(6)]))
    return ("/" + "/".join(parts)) if parts else ""

def random_query():
    if random.random() < 0.25:
        k = random.choice(["ref","id","m","r","token","next"])
        v = rand_token(6)
        return "?" + k + "=" + v
    return ""

def make_url(host, tld, sub=None, path="", query=""):
    if sub:
        host_full = f"{sub}.{host}{tld}"
    else:
        host_full = f"{host}{tld}"
    scheme = "https://" if random.random() < 0.7 else "http://"
    return f"{scheme}{host_full}{path}{query}"

# -------------------------
# Build pool deterministically then randomize
# -------------------------
pool = []

# 1) Pattern-based + TLD + optional subdomains
for brand in BRANDS:
    for pat in PATTERNS:
        for tld in TLDS:
            host = pat.format(brand=brand)
            pool.append(make_url(host, tld, sub=None, path="", query=""))
            sub = random.choice(SUBS)
            pool.append(make_url(host, tld, sub=sub, path="", query=""))
            p = "/" + random.choice(["login","secure","account"]) + "/" + rand_token(5)
            q = "?ref=" + rand_token(6) if random.random() < 0.3 else ""
            pool.append(make_url(host, tld, sub=None, path=p, query=q))

# 2) Typosquatting + TLD + variations
for brand in BRANDS:
    typos = list(typos_for(brand))
    # sample more variations for larger output
    for typo in typos[:15]:
        for tld in random.sample(TLDS, k=min(8,len(TLDS))):
            sub = random.choice([None] + SUBS)
            path = random_path()
            pool.append(make_url(typo, tld, sub=sub, path=path, query=random_query()))

# 3) Brand domain + suspicious path variants
for brand in BRANDS:
    for _ in range(8):  # increased multiplicity
        tld = random.choice(TLDS)
        sub = random.choice(SUBS + [None])
        host = brand
        p = "/" + random.choice(["secure","signin","verify","account","auth","user"]) + "/" + rand_token(5)
        q = random_query()
        pool.append(make_url(host, tld, sub=sub, path=p, query=q))

# 4) Mixed-brand combos to simulate lookalikes
for a,b in itertools.permutations(BRANDS[:50], 2):
    if random.random() < 0.03:
        tld = random.choice(TLDS)
        host = f"{a}-{b}"
        pool.append(make_url(host, tld, sub=random.choice([None,"www","login"]), path=random_path(), query=random_query()))

# 5) Numeric and token suffix/prefix combos
for brand in BRANDS:
    for num in (str(random.randint(10,999)), str(random.randint(1000,9999)), str(random.randint(10000,99999))):
        tld = random.choice(TLDS)
        host = f"{brand}{num}"
        pool.append(make_url(host, tld, sub=None, path=random_path(), query=random_query()))

# 6) Add random crafted hosts until pool large enough
while len(pool) < TARGET * 3:  # build a larger pool to sample diverse unique items
    brand = random.choice(BRANDS)
    variant_candidates = list(typos_for(brand))
    variant = random.choice(variant_candidates) if variant_candidates else brand
    tld = random.choice(TLDS)
    sub = random.choice([None] + SUBS)
    host = random.choice([
        f"{variant}-{random.choice(['secure','login','verify','auth'])}",
        f"{variant}{random.choice(['','-','_'])}{rand_token(3)}",
        f"{variant}{random.choice(['','auth','portal','pay'])}"
    ])
    path = random_path()
    q = random_query()
    pool.append(make_url(host, tld, sub=sub, path=path, query=q))

# -------------------------
# Finalize unique + sample TARGET
# -------------------------
normalized = list(dict.fromkeys(pool))  # deduplicate preserving order
random.shuffle(normalized)

if len(normalized) < TARGET:
    raise SystemExit(f"Pool too small: {len(normalized)} < {TARGET}")

final = normalized[:TARGET]

# Ensure host diversity
hosts = set()
diverse_final = []
for u in final:
    host = u.split("://",1)[1].split("/",1)[0]
    if host not in hosts or random.random() < 0.12:
        diverse_final.append(u)
        hosts.add(host)
    if len(diverse_final) >= TARGET:
        break

if len(diverse_final) < TARGET:
    diverse_final = final[:TARGET]

# -------------------------
# Save CSV with 'url' and 'type'
# -------------------------
OUTFILE.parent.mkdir(parents=True, exist_ok=True)
with OUTFILE.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["url", "type"])
    for u in diverse_final:
        writer.writerow([u, "phishing"])

print(f"✅ Generated {len(diverse_final)} phishing-like URLs -> {OUTFILE.resolve()}")

