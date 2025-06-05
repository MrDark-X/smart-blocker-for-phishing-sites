from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
import re
import numpy as np
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import pandas as pd
import pickle
import os
from dotenv import load_dotenv
import tldextract  # <-- Add this line

# --- Load Environment Variables (for APIs, if needed) ---
load_dotenv()
MOZ_ACCESS_ID = os.getenv("MOZ_ACCESS_ID")
MOZ_SECRET_KEY = os.getenv("MOZ_SECRET_KEY")
SERPAPI_KEY = os.getenv("SERPAPI_KEY")

# --- Load Trained Models ---
with open("phishing_svm_model.pkl", "rb") as f:
    svm_pipeline = pickle.load(f)
with open("phishing_knn_model.pkl", "rb") as f:
    knn_pipeline = pickle.load(f)
with open("phishing_rf_model.pkl", "rb") as f:
    rf_pipeline = pickle.load(f)

# --- Define Feature Lists ---
all_features = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq',
    'nb_slash', 'nb_www', 'ratio_digits_url', 'ratio_digits_host',
    'tld_in_subdomain', 'prefix_suffix', 'shortest_word_host',
    'longest_words_raw', 'longest_word_path', 'phish_hints',
    'nb_hyperlinks', 'ratio_intHyperlinks', 'empty_title',
    'domain_in_title', 'domain_age', 'google_index', 'page_rank'
]
auto_features = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq',
    'nb_slash', 'nb_www', 'ratio_digits_url', 'ratio_digits_host',
    'tld_in_subdomain', 'prefix_suffix', 'shortest_word_host',
    'longest_words_raw', 'longest_word_path', 'phish_hints'
]
manual_features = list(set(all_features) - set(auto_features))
manual_features.sort()

# --- Feature Extraction Functions ---
def extract_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0,
        'nb_dots': url.count('.'),
        'nb_qm': url.count('?'),
        'nb_eq': url.count('='),
        'nb_slash': url.count('/'),
        'nb_www': url.count('www'),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0,
        'tld_in_subdomain': int(any(tld in hostname.split('.')[:-1] for tld in ['com', 'net', 'org'])),
        'prefix_suffix': int('-' in hostname),
        'shortest_word_host': min((len(w) for w in hostname.split('.')), default=0),
        'longest_words_raw': max((len(w) for w in url.split('/')), default=0),
        'longest_word_path': max((len(w) for w in path.split('/')), default=0),
        'phish_hints': int(any(k in url.lower() for k in ['secure', 'login', 'paypal', 'ebay', 'bank']))
    }
    return features

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days if creation else 0
        print(f"Domain: {domain}, Age: {age} days")
        return age
    except Exception:
        return 0

def get_title_features(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        title = soup.title.string if soup.title else ""
        hostname = urlparse(url).hostname or ""
        print(f"Title: {title}, Hostname: {hostname}")
        return {
            "empty_title": int(title.strip() == ""),
            "domain_in_title": int(hostname.lower().split('.')[0] in title.lower()) if title else 0
        }
    except Exception:
        return {"empty_title": 1, "domain_in_title": 0}

def get_page_rank(url):
    try:
        endpoint = f"https://lsapi.seomoz.com/v2/url_metrics"
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            endpoint,
            json={"targets": [url]},
            auth=(MOZ_ACCESS_ID, MOZ_SECRET_KEY),
            headers=headers
        )
        print(f"Page Rank for : {response.json()['results'][0]['page_authority']}")
        return response.json()["results"][0]["page_authority"]
    except Exception:
        return 0

def is_google_indexed(url):
    try:
        search_url = f"https://serpapi.com/search?engine=google&q=site:{url}&api_key={SERPAPI_KEY}"
        res = requests.get(search_url).json()
        print(f"Google Indexed: {1 if res.get('organic_results') else 0}")
        return 1 if res.get("organic_results") else 0
    except Exception:
        return 0

# --- Trusted Domains (Whitelisting) ---
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "zoom.us", "outlook.com", "microsoft.com",
    "amazon.com", "maps.google.com", "meet.google.com", "gmail.com",
    "facebook.com", "instagram.com", "linkedin.com", "apple.com", "dropbox.com",
    "slack.com", "adobe.com", "drive.google.com", "calendar.google.com",
    "mail.yahoo.com", "twitter.com", "github.com", "whatsapp.com",
    "pinterest.com", "reddit.com", "tumblr.com", "flickr.com", "vimeo.com",
    "wordpress.com", "wikipedia.org", "quora.com", "stackoverflow.com",
    "paypal.com", "ebay.com", "craigslist.org", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "capitalone.com", "usbank.com",
    "citi.com", "americanexpress.com", "discover.com", "barclays.com",
    "hsbc.com", "td.com", "scotiabank.com", "royalbank.com", "bmo.com",
    "tdameritrade.com", "etrade.com", "fidelity.com", "vanguard.com",
    "robinhood.com", "coinbase.com", "binance.com", "kraken.com",
    "blockchain.com", "bitstamp.net", "gemini.com", "bitfinex.com",
    "poloniex.com", "bittrex.com", "kucoin.com", "okex.com", "huobi.com",
    "bitmex.com", "deribit.com", "bybit.com", "phemex.com", "ftx.com",
    "bitso.com", "bitbank.cc", "liquid.com", "gate.io", "cobinhood.com",
    "bitmart.com", "hotbit.io", "probit.com", "biki.com", "zbg.com","hotstar.com","chrome.com","kaggle.com","yashinfosec.com"
]

def get_base_domain(hostname):
    ext = tldextract.extract(hostname)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    else:
        return hostname

# --- FastAPI Setup ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

@app.post("/predict")
async def predict(request: Request):
    data = await request.json()
    url = data.get("url")
    model_choice = data.get("model", "Random Forest")
    manual_inputs = data.get("manual_inputs", [])

    if not url:
        return {"error": "URL is required!"}

    # --- Extract hostname and check whitelist ---
    hostname = urlparse(url).hostname or ""
    base_domain = get_base_domain(hostname)

    if base_domain in TRUSTED_DOMAINS:
        return {
            "prediction": "Legitimate ✅ (trusted domain)",
            "features": [{"Feature": "trusted_domain", "Value": 1, "Source": "Whitelist"}],
            "block_site": False
        }

    # --- Feature Extraction ---
    auto_vals = extract_from_url(url)

    # API-based features (optional, skip if keys are not set)
    auto_vals['domain_age'] = get_domain_age(hostname)
    auto_vals['page_rank'] = get_page_rank(url) if MOZ_ACCESS_ID and MOZ_SECRET_KEY else 0
    auto_vals['google_index'] = is_google_indexed(url) if SERPAPI_KEY else 0
    title_feats = get_title_features(url)
    auto_vals.update(title_feats)

    manual_features_remaining = [f for f in manual_features if f not in auto_vals]
    manual_vals = dict(zip(manual_features_remaining, manual_inputs))

    # --- Prepare input for model ---
    full_input = []
    feature_rows = []
    for f in all_features:
        if f in auto_vals:
            val = auto_vals[f]
            source = "Auto/API"
        elif f in manual_vals:
            val = manual_vals[f]
            source = "Manual"
        else:
            val = 0  # Default/fallback
            source = "Manual"
        full_input.append(val)
        feature_rows.append({"Feature": f, "Value": val, "Source": source})

    X = np.array(full_input).reshape(1, -1)

    # --- Model Prediction ---
    if model_choice == "SVM":
        prediction = svm_pipeline.predict(X)[0]
    elif model_choice == "KNN":
        prediction = knn_pipeline.predict(X)[0]
    else:  # Random Forest default
        prediction = rf_pipeline.predict(X)[0]

    result_str = "Phishing 🚨 " if prediction == 1 else "Legitimate ✅"
    block_site=True if prediction == 1 else False

    return {
        "prediction": result_str,
        "features": feature_rows,
        "block_site": block_site
    }

# To run the server:
# uvicorn api_server:app --reload
