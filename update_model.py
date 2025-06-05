
import pandas as pd
import requests
import pickle
import re
from urllib.parse import urlparse
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

# ----------- Step 1: Download Fresh Data from PhishTank  ------------
def get_latest_phishing_urls(limit=50):
    phishing_urls = [
        "http://badlogin.com/login",
        "http://fakepaypal.verify-user.info",
        "http://banksecure-update.com",
    ]
    return phishing_urls[:limit]

# ----------- Step 2: Simulated Legitimate URLs ------------
def get_legitimate_urls():
    return [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
    ]

# ----------- Step 3: Feature Extraction (Basic from existing logic) ------------
def extract_features(url):
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

# ----------- Step 4: Build Dataset ------------
def build_dataset():
    phishing_urls = get_latest_phishing_urls()
    legit_urls = get_legitimate_urls()

    data = []

    for url in phishing_urls:
        f = extract_features(url)
        f['status'] = 1
        data.append(f)

    for url in legit_urls:
        f = extract_features(url)
        f['status'] = 0
        data.append(f)

    df = pd.DataFrame(data)
    return df

# ----------- Step 5: Retrain Model ------------
def retrain_model(df):
    X = df.drop(columns=["status"])
    y = df["status"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.25, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, max_depth=20)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    # Save model and scaler
    with open("phishing_rf_model.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open("scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print(f"✅ Model retrained successfully with accuracy: {acc * 100:.2f}%")



if __name__ == "__main__":
    df = build_dataset()
    retrain_model(df)
