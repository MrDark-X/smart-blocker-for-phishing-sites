## 📘 README.md for GitHub: Smart Blocker of Phishing Websites

### 🔒 Project Title

**Smart Blocker of Phishing Websites**

### 🧠 Overview

This project presents a comprehensive, AI-powered solution for **real-time phishing detection** through a combination of machine learning, a FastAPI backend server, and a Chrome browser extension. It helps users **identify, warn, and block access** to malicious phishing websites with high accuracy.

---

### 🚀 Features

* Real-time URL phishing classification
* Trained ML models (Random Forest, SVM, KNN)
* FastAPI-based prediction backend
* Chrome extension for automatic blocking
* Dynamic popup UI with model and feature visualization
* Automated model updater to stay ahead of emerging threats

---

### 📁 Project Structure

```
├── phishing_url_detection_96_accuracy.ipynb   # Model training and evaluation
├── dataset_phishing.csv                        # Dataset of phishing and legitimate URLs
├── api_server.py                               # FastAPI backend server
├── model_updater.py                            # Script to update model using fresh data
├── chrome_extension/
│   ├── manifest.json                           # Chrome extension metadata
│   ├── background.js                           # Handles URL capture
│   ├── content.js                              # Injects overlay
│   ├── popup.js                                # UI logic
│   ├── popup.html                              # Popup UI
│   ├── popup.css                               # Styling
│   └── icon.png                                # Extension icon
└── README.md                                   # This file
```

---

### ⚙️ Installation and Usage

#### ✅ 1. Train or Load Pre-trained Model

Use the Jupyter notebook `phishing_url_detection_96_accuracy.ipynb` to train or test the ML models.

#### ✅ 2. Start FastAPI Backend

```bash
python api_server.py
# Runs at http://localhost:8000
```

#### ✅ 3. Load Chrome Extension

* Go to `chrome://extensions/`
* Enable **Developer Mode**
* Click on **Load unpacked**
* Select the `chrome_extension/` folder

#### ✅ 4. Visit Any Website

The extension will analyze the URL in real time. If phishing is detected, a red overlay will block the page. The popup shows features and prediction.

#### ✅ 5. Update Model with Fresh Data

```bash
python model_updater.py
```

This will retrain the model with latest phishing URLs and replace the model file used by the backend.

---

### 📊 Model Performance

* Accuracy: **96.8%** (Random Forest)
* Precision: 97.1%
* Recall: 96.3%
* Response time: <150ms end-to-end

---

### 📚 Tech Stack

* Python (scikit-learn, pandas, FastAPI)
* JavaScript (Chrome Extension APIs)
* HTML5/CSS3
* Jupyter Notebook

---

### ✍️ Author

**Yaswanth Surya Chalamalasetty**
Cybersecurity Researcher | SOC Analyst | AI-Security Enthusiast

---

## ✨ Blog: How We Built the Smart Blocker of Phishing Websites

### 🧩 Introduction

Phishing websites are one of the most common cyber threats, tricking users into sharing sensitive information. I wanted to build something that not only **detects** these sites but also **blocks them in real-time**—without user intervention. This project is the result of that vision.

### 📐 Objective

To create an intelligent browser extension that uses machine learning to detect phishing websites, backed by a real-time API server, and notify/block users instantly.

---

### 🔬 Phase 1: Data Collection & Model Training

I began by collecting a dataset of 11,000+ URLs (legitimate + phishing). Using this:

* I engineered 20+ features such as URL length, IP usage, presence of @ symbol, redirection count, domain age, etc.
* Trained **Random Forest, SVM, and KNN** models.
* The Random Forest model achieved **96.8% accuracy**.
* I saved the model using `pickle`.

📌 *Tools used: pandas, scikit-learn, matplotlib, seaborn*

---

### 🌐 Phase 2: Backend API with FastAPI

To serve predictions, I built an API using **FastAPI**:

* Endpoint: `/predict`
* Accepts URL and model name
* Extracts features and returns JSON response

Example Response:

```json
{
  "prediction": "phishing",
  "features": {
    "length_url": 82,
    "has_ip": true,
    ...
  }
}
```

---

### 🧩 Phase 3: Chrome Extension

I created a Chrome Extension with:

* `background.js` to intercept active tab URLs
* `popup.html` + `popup.js` to show prediction & features
* `content.js` to inject a red overlay on phishing pages
* `manifest.json` to configure extension permissions

The extension communicates with FastAPI to get real-time predictions.

---

### 🔁 Phase 4: Automated Model Update

To keep up with phishing trends, I built `model_updater.py`:

* Fetches fresh phishing data from sources like PhishTank or OpenPhish
* Retrains the ML model
* Replaces the old model file

This ensures the system evolves with new threats.

---

### 📊 Testing & Performance

* Tested on real phishing sites
* Full-page overlay for blocked sites
* Prediction latency: \~100ms
* Popup UI is intuitive for non-technical users

---

### 🔒 Security and Privacy

* No URLs are stored or logged.
* Everything runs locally unless deployed to a secure backend.
* Chrome extension works in sandboxed mode.

---

### 🧠 Final Thoughts

Building this project helped me understand the full pipeline:

* Data to AI model
* Backend API
* Frontend integration
* Real-world usability

It’s an example of how **AI and browser automation** can work together to protect users—silently and effectively.

---

### 📎 Want to Use or Contribute?

GitHub: [Smart Blocker Repository](https://github.com/MrDark-X)

Reach out for suggestions, improvements, or collaboration!

---

If you’d like this blog converted to HTML or published format, let me know!
