chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === "complete" && /^https?:/.test(tab.url)) {
    fetch("http://localhost:8000/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        url: tab.url,
        model: "KNN",
        manual_inputs: [0, 0]
      })
    })
    .then(res => res.json())
    .then(data => {
      if (data.prediction && data.prediction.toLowerCase().includes("phishing")) {
        chrome.action.setBadgeText({tabId: tabId, text: "⚠️"});
        chrome.action.setBadgeBackgroundColor({tabId: tabId, color: "#d32f2f"});
      } else {
        chrome.action.setBadgeText({tabId: tabId, text: ""});
      }
    });
  }
});
