(async function() {
  // Avoid running in iframes or ad frames
  if (window.top !== window.self) return;

  // Only run on http(s) pages
  if (!/^https?:/.test(window.location.href)) return;

  const apiUrl = "http://localhost:8000/predict";
  const url = window.location.href;
  const data = {
    url: url,
    model: "KNN", // or "RandomForest" etc
    manual_inputs: [0, 0] // Adjust based on your backend requirements
  };

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(data)
    });
    const result = await response.json();

    // BLOCK user if site is phishing
    if (result.block_site === true) {
      // Remove all page content
      document.body.innerHTML = "";

      // Create blocking overlay
      const overlay = document.createElement('div');
      overlay.innerHTML = `
        <div style="display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;">
          <div style="background:#fff;border-radius:10px;padding:32px 40px;box-shadow:0 4px 24px rgba(0,0,0,0.2);text-align:center;">
            <div style="font-size:2em;color:#d32f2f;margin-bottom:12px;">🚫 Blocked for your safety!</div>
            <div style="font-size:1.2em;color:#444;">
              This site has been flagged as a <b>phishing website</b>.<br>
              Access has been <b>blocked</b> to protect you.
            </div>
          </div>
        </div>
      `;
      overlay.style.position = "fixed";
      overlay.style.top = "0";
      overlay.style.left = "0";
      overlay.style.width = "100vw";
      overlay.style.height = "100vh";
      overlay.style.background = "rgba(211,47,47, 0.97)";
      overlay.style.zIndex = "2147483647";
      overlay.style.pointerEvents = "all";
      overlay.style.margin = "0";
      overlay.style.padding = "0";
      overlay.style.boxSizing = "border-box";

      document.body.appendChild(overlay);
      document.body.style.overflow = "hidden";
      return;
    }

    // If not blocked, but still suspicious, show a warning banner (optional)
    if (result.prediction && result.prediction.toLowerCase().includes("phishing")) {
      const banner = document.createElement('div');
      banner.innerHTML = "⚠️ <strong>Warning: This site may be a phishing website!</strong> ⚠️";
      banner.style.position = "fixed";
      banner.style.top = "0";
      banner.style.left = "0";
      banner.style.width = "100%";
      banner.style.background = "#d32f2f";
      banner.style.color = "#fff";
      banner.style.textAlign = "center";
      banner.style.padding = "12px 0";
      banner.style.fontSize = "1.2em";
      banner.style.zIndex = "999999";
      banner.style.boxShadow = "0 2px 10px rgba(0,0,0,0.2)";
      document.body.prepend(banner);
    }
  } catch (err) {
    // Optionally handle API errors or log
    // console.error("Phishing detection API error:", err);
  }
})();
