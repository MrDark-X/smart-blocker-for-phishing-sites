import gradio as gr
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

# Load environment variables from .env
load_dotenv()

MOZ_ACCESS_ID = os.getenv("MOZ_ACCESS_ID")
MOZ_SECRET_KEY = os.getenv("MOZ_SECRET_KEY")
SERPAPI_KEY = os.getenv("SERPAPI_KEY")


with open("phishing_svm_model.pkl", "rb") as f:
    svm_pipeline = pickle.load(f)
with open("phishing_knn_model.pkl", "rb") as f:
    knn_pipeline = pickle.load(f)
with open("phishing_rf_model.pkl", "rb") as f:
    rf_pipeline = pickle.load(f)




# Map features to their source
feature_sources = {
    # Auto-extracted features
    'length_url': 'Calculated from URL', 'length_hostname': 'Calculated from URL', 'ip': 'Calculated from URL', 'nb_dots': 'Calculated from URL',
    'nb_qm': 'Calculated from URL', 'nb_eq': 'Calculated from URL', 'nb_slash': 'Calculated from URL', 'nb_www': 'Calculated from URL',
    'ratio_digits_url': 'Calculated from URL', 'ratio_digits_host': 'Calculated from URL', 'tld_in_subdomain': 'Calculated from URL',
    'prefix_suffix': 'Calculated from URL', 'shortest_word_host': 'Calculated from URL', 'longest_words_raw': 'Calculated from URL',
    'longest_word_path': 'Calculated from URL', 'phish_hints': 'Calculated from URL',
    # API-extracted features
    'domain_age': 'API', 'google_index': 'API', 'page_rank': 'API',
    'empty_title': 'API', 'domain_in_title': 'API'
  
}


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
    # print(features)
    return features

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days if creation else 0
        return age
    except Exception as e:
        return 0

def get_title_features(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        title = soup.title.string if soup.title else ""
        hostname = urlparse(url).hostname or ""
        return {
            "empty_title": int(title.strip() == ""),
            "domain_in_title": int(hostname.lower().split('.')[0] in title.lower()) if title else 0
        }
    except:
        return {"empty_title": 1, "domain_in_title": 0}

def get_page_rank(url):
    # Uncomment if you have Moz API credentials
    endpoint = f"https://lsapi.seomoz.com/v2/url_metrics"
    headers = {"Content-Type": "application/json"}
    response = requests.post(
        endpoint,
        json={"targets": [url]},
        auth=(MOZ_ACCESS_ID, MOZ_SECRET_KEY),
        headers=headers
    )
    return response.json()["results"][0]["page_authority"]
  
    # return 0  # Placeholder for demo

def is_google_indexed(url):
    # Uncomment if you have SerpAPI
    search_url = f"https://serpapi.com/search?engine=google&q=site:{url}&api_key={SERPAPI_KEY}"
    res = requests.get(search_url).json()
    return 1 if res.get("organic_results") else 0

    # return 0  # Placeholder for demo

def predict_from_url(url, model_choice, *manual_inputs):
    auto_vals = extract_from_url(url)
    hostname = urlparse(url).hostname or ""

    # API features
    auto_vals['domain_age'] = get_domain_age(hostname)
    auto_vals['page_rank'] = get_page_rank(url)
    auto_vals['google_index'] = is_google_indexed(url)
    title_feats = get_title_features(url)
    auto_vals.update(title_feats)

    manual_features_remaining = [f for f in manual_features if f not in auto_vals]
    manual_vals = dict(zip(manual_features_remaining, manual_inputs))

    # Build input
    full_input = []
    feature_rows = []
    for f in all_features:
        if f in auto_vals:
            val = auto_vals[f]
            source = feature_sources.get(f, "Auto")
        elif f in manual_vals:
            val = manual_vals[f]
            source = "Manual"
        else:
            val = None
            source = "Manual"
        full_input.append(val)
        feature_rows.append({"Feature": f, "Value": val, "Source": source})

    X = np.array(full_input).reshape(1, -1)
    # Model selection
    if model_choice == "SVM":
        prediction = svm_pipeline.predict(X)[0]
    elif model_choice == "Random Forest":
        prediction = rf_pipeline.predict(X)[0]
    else:  # KNN
        prediction = knn_pipeline.predict(X)[0]

    result_str = "Phishing 🚨 (1)" if prediction == 1 else "Legitimate ✅ (0)"
    df = pd.DataFrame(feature_rows)
    return result_str, df


# Manual features needed for input
manual_inputs = [gr.Number(label=f"{f} (manual)") for f in manual_features if f not in [
    'domain_age', 'page_rank', 'google_index', 'empty_title', 'domain_in_title'
]]

app = gr.Interface(
    fn=predict_from_url,
    inputs=[
        gr.Text(label="Enter URL"),
        gr.Dropdown(choices=["SVM", "KNN", "Random Forest"], label="Choose Model", value="KNN"),
        *manual_inputs
    ],
    outputs=[
        gr.Text(label="Prediction"),
        gr.Dataframe(label="Calculated Features Table")
    ],
    title="🔍 Advanced URL Phishing Detector",
    description="See all extracted and provided features, their values, and their source (Auto, API, Manual)."
)

app.launch(share=True, debug=True)
