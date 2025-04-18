// content.js
// Content script with improved security features
(function() {
    // Track processed links to avoid redundant checks
    const processedLinks = new Set();
    
    // Create and inject CSS for warning elements
    function injectStyles() {
      const style = document.createElement('style');
      style.textContent = `
        .phishguard-warning-banner {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          background-color: #fef7e0;
          color: #ea8600;
          padding: 12px;
          z-index: 999999;
          font-family: Arial, sans-serif;
          display: flex;
          justify-content: space-between;
          align-items: center;
          box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .phishguard-warning-icon {
          margin-right: 10px;
          font-size: 20px;
        }
        
        .phishguard-warning-message {
          flex-grow: 1;
        }
        
        .phishguard-warning-actions {
          display: flex;
          gap: 10px;
        }
        
        .phishguard-warning-actions button {
          padding: 6px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: bold;
          border: none;
        }
        
        .phishguard-proceed-button {
          background-color: #f8f9fa;
          color: #5f6368;
          border: 1px solid #dadce0 !important;
        }
        
        .phishguard-back-button {
          background-color: #4285f4;
          color: white;
        }
        
        .phishguard-close-button {
          background: none;
          border: none;
          cursor: pointer;
          font-size: 18px;
        }
        
        .phish-risk-indicator {
          margin-left: 5px;
          font-size: 14px;
          cursor: help;
        }
      `;
      document.head.appendChild(style);
    }
    
    // Show warning banner for medium-risk sites
    function showWarningBanner(url, assessment) {
      // Remove any existing banner
      const existingBanner = document.querySelector('.phishguard-warning-banner');
      if (existingBanner) {
        existingBanner.remove();
      }
      
      // Create new banner
      const banner = document.createElement('div');
      banner.className = 'phishguard-warning-banner';
      
      // Format the risk score as percentage
      const riskPercentage = Math.round(assessment.riskScore * 100);
      
      // Get the top reason
      const topReason = assessment.reasons && assessment.reasons.length > 0 
        ? assessment.reasons[0] 
        : "Suspicious URL detected";
      
      banner.innerHTML = `
        <div class="phishguard-warning-icon">⚠️</div>
        <div class="phishguard-warning-message">
          <strong>Warning:</strong> This site shows signs of being a phishing attempt. 
          Risk score: ${riskPercentage}%. ${topReason}
        </div>
        <div class="phishguard-warning-actions">
          <button class="phishguard-back-button">Go Back</button>
          <button class="phishguard-proceed-button">Proceed Anyway</button>
        </div>
        <button class="phishguard-close-button">×</button>
      `;
      
      // Add to document
      document.body.insertAdjacentElement('afterbegin', banner);
      
      // Add event listeners
      banner.querySelector('.phishguard-back-button').addEventListener('click', () => {
        window.history.back();
      });
      
      banner.querySelector('.phishguard-proceed-button').addEventListener('click', () => {
        banner.remove();
      });
      
      banner.querySelector('.phishguard-close-button').addEventListener('click', () => {
        banner.remove();
      });
    }
    
    // Mark links based on risk level
    function markLinkByRiskLevel(link, riskAssessment) {
      // Remove any existing markers
      const existingMarker = link.querySelector('.phish-risk-indicator');
      if (existingMarker) existingMarker.remove();
      
      // Create new risk indicator
      const riskIndicator = document.createElement('span');
      riskIndicator.classList.add('phish-risk-indicator');
      
      const riskLevel = riskAssessment.riskScore;
      
      if (riskLevel > 0.8) {
        // High risk - Red indicator
        riskIndicator.innerHTML = '🔴';
        riskIndicator.title = 'High-risk phishing site';
        link.style.textDecoration = 'line-through';
        
        // Full-page interception
        link.addEventListener('click', function(e) {
          e.preventDefault();
          if (confirm('This link appears to be a high-risk phishing attempt. Do you still want to proceed?')) {
            window.open(link.href, '_blank');
          }
        });
      } 
      else if (riskLevel > 0.4) {
        // Medium risk - Orange indicator
        riskIndicator.innerHTML = '🟠';
        riskIndicator.title = 'Suspicious link';
        
        // Warning with proceed option
        link.addEventListener('click', function(e) {
          e.preventDefault();
          if (confirm('This link appears suspicious. Proceed with caution?')) {
            window.open(link.href, '_blank');
          }
        });
      }
      else {
        // Low/No risk - Green indicator (optional)
        riskIndicator.innerHTML = '🟢';
        riskIndicator.title = 'Link appears safe';
      }
      
      link.appendChild(riskIndicator);
    }
    
    // Check all links on page
    function checkPageLinks() {
      const links = document.querySelectorAll('a[href]:not([data-phishguard-checked])');
      
      links.forEach(link => {
        const url = link.href;
        
        // Mark as processed
        link.setAttribute('data-phishguard-checked', 'true');
        processedLinks.add(link);
        
        if (url.startsWith('http')) {
          chrome.runtime.sendMessage(
            { action: "checkUrl", url: url },
            response => {
              if (response) {
                // Mark link based on risk level
                markLinkByRiskLevel(link, response);
              }
            }
          );
        }
      });
    }
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === "showWarningBanner") {
            showWarningBanner(message.url, message.assessment);
            sendResponse({ success: true });
          }
          
          if (message.action === "forceCheck") {
            checkPageLinks();
            sendResponse({ success: true });
          }
          
          return true;
        });
        
        // Run initial setup
        function initialize() {
          injectStyles();
          checkPageLinks();
          
          // Observe DOM changes to check new links
          const observer = new MutationObserver(mutations => {
            let hasNewLinks = false;
            
            mutations.forEach(mutation => {
              if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                // Check if any new links were added
                for (let i = 0; i < mutation.addedNodes.length; i++) {
                  const node = mutation.addedNodes[i];
                  if (node.nodeName === 'A' || (node.querySelectorAll && node.querySelectorAll('a[href]').length > 0)) {
                    hasNewLinks = true;
                    break;
                  }
                }
              }
            });
            
            if (hasNewLinks) {
              checkPageLinks();
            }
          });
          
          observer.observe(document.body, {
            childList: true,
            subtree: true
          });
        }
        
        // Check if document is already loaded
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initialize);
        } else {
          initialize();
        }
      })();