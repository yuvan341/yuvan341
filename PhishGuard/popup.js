// popup.js
document.addEventListener('DOMContentLoaded', function() {
    const statusDiv = document.getElementById('status');
    const detailsDiv = document.getElementById('details');
    const checkPageButton = document.getElementById('checkPage');
    const protectionLevelSelect = document.getElementById('protectionLevel');
    const telemetryOpt = document.getElementById('telemetryOpt');
    const autoUpdateModel = document.getElementById('autoUpdateModel');
    
    // Load settings
    chrome.storage.sync.get(['protectionLevel', 'telemetrySettings', 'autoUpdateModel'], function(result) {
      if (result.protectionLevel) {
        protectionLevelSelect.value = result.protectionLevel;
      }
      
      if (result.telemetrySettings?.optIn) {
        telemetryOpt.checked = true;
      }
      
      if (result.autoUpdateModel !== undefined) {
        autoUpdateModel.checked = result.autoUpdateModel;
      }
    });
    
    // Save settings when changed
    protectionLevelSelect.addEventListener('change', function() {
      chrome.storage.sync.set({ protectionLevel: this.value });
    });
    
    telemetryOpt.addEventListener('change', function() {
      chrome.runtime.sendMessage({
        action: "setTelemetrySettings",
        settings: { optIn: this.checked }
      });
    });
    
    autoUpdateModel.addEventListener('change', function() {
      chrome.storage.sync.set({ autoUpdateModel: this.checked });
    });
    
    // Get stats from background script
    chrome.runtime.sendMessage({ action: "getStats" }, response => {
      if (response) {
        document.getElementById('urlsChecked').textContent = response.urlsChecked;
        document.getElementById('phishingDetected').textContent = response.phishingDetected;
        document.getElementById('lastUpdated').textContent = response.lastUpdated;
      }
    });
    
    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      const currentUrl = tabs[0].url;
      
      // Skip checking for chrome:// URLs
      if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://')) {
        statusDiv.className = 'status safe';
        statusDiv.textContent = 'Chrome internal page (safe)';
        return;
      }
      
      // Check current URL
      chrome.runtime.sendMessage(
        { action: "checkUrl", url: currentUrl },
        response => {
          if (response) {
            updateStatusDisplay(response);
          } else {
            statusDiv.className = 'status warning';
            statusDiv.textContent = 'Unable to check this URL';
          }
        }
      );
    });
    
    // Update the status display based on risk assessment
    function updateStatusDisplay(assessment) {
      const riskScore = assessment.riskScore;
      const riskPercentage = Math.round(riskScore * 100);
      
      if (riskScore > 0.7) {
        // High risk
        statusDiv.className = 'status danger';
        statusDiv.textContent = '⚠️ High-risk phishing site detected!';
      } 
      else if (riskScore > 0.4) {
        // Medium risk
        statusDiv.className = 'status warning';
        statusDiv.textContent = '⚠️ Suspicious site detected';
      } 
      else {
        // Low risk
        statusDiv.className = 'status safe';
        statusDiv.textContent = '✅ No phishing detected';
      }
      
      // Display risk details
      let detailsHtml = `
        <div class="risk-details">
          <span>Risk:</span>
          <div class="risk-meter">
            <div class="risk-indicator" style="left: ${riskPercentage}%"></div>
          </div>
          <span>${riskPercentage}%</span>
        </div>
      `;
      
      // Show reasons if available
      if (assessment.reasons && assessment.reasons.length > 0) {
        detailsHtml += '<div id="reasons"><strong>Reasons:</strong><ul>';
        assessment.reasons.forEach(reason => {
          detailsHtml += `<li>${reason}</li>`;
        });
        detailsHtml += '</ul></div>';
      }
      
      detailsDiv.innerHTML = detailsHtml;
    }
    
    // Handle manual check button
    checkPageButton.addEventListener('click', function() {
      statusDiv.className = 'status warning';
      statusDiv.textContent = 'Analyzing page links...';
      
      chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "forceCheck" }, response => {
          if (response && response.success) {
            statusDiv.className = 'status safe';
            statusDiv.textContent = '✅ Page analysis complete';
          } else {
            statusDiv.className = 'status warning';
            statusDiv.textContent = 'Unable to analyze all links';
          }
        });
      });
    });
});