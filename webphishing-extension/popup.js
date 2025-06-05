// Autofill URL input with current tab's URL and auto-predict
window.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    let url = tabs[0].url || '';
    document.getElementById('url').value = url;

    // Trigger auto-prediction on popup open
    if (url.startsWith('http')) {
      autoPredict(url);
    }
  });
});

// Listen for form submit to allow manual prediction (model change or URL change)
document.getElementById('predict-form').addEventListener('submit', function(e) {
  e.preventDefault();
  const url = document.getElementById('url').value;
  autoPredict(url);
});

function autoPredict(url) {
  const model = document.getElementById('model').value;
  const resultDiv = document.getElementById('result');
  const table = document.getElementById('features-table');
  const tbody = table.querySelector('tbody');
  resultDiv.textContent = "Checking...";
  table.style.display = "none";
  tbody.innerHTML = "";

  // Backend API endpoint
  fetch('http://localhost:8000/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      url: url,
      model: model,
      manual_inputs: [0, 0] // Adjust if you have required manual features
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      resultDiv.textContent = data.error;
      return;
    }
    resultDiv.innerHTML = `<strong>${data.prediction}</strong>`;
    // Fill the features table
    if (data.features && data.features.length > 0) {
      data.features.forEach(feat => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${feat.Feature}</td><td>${feat.Value}</td><td>${feat.Source}</td>`;
        tbody.appendChild(row);
      });
      table.style.display = "";
    }
  })
  .catch(err => {
    resultDiv.textContent = "Error connecting to backend.";
  });
}

// Optional: allow model dropdown change to re-predict immediately
document.getElementById('model').addEventListener('change', function() {
  const url = document.getElementById('url').value;
  if (url.startsWith('http')) {
    autoPredict(url);
  }
});
