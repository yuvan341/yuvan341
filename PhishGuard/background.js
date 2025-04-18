// background.js
// Enhanced phishing detection service with security improvements

// Configuration
const ML_API_ENDPOINT = "https://api.phishguard.example.com/analyze";
const TELEMETRY_ENDPOINT = "https://telemetry.phishguard.example.com/collect";
const TELEMETRY_SETTINGS_KEY = 'telemetrySettings';
const MIN_ANALYSIS_INTERVAL = 86400000; // 24 hours in milliseconds

// Known phishing domains list
const KNOWN_PHISHING_DOMAINS = [
  "paypa1.com", "amaz0n.com", "g00gle.com", "faceb00k.com", 
  "apple-id-verify.com", "secure-banklogin.com", "login-verification.net",
  "account-update.info", "signin-secure.com", "verify-account.co"
];

// Local cache for previously checked URLs
let urlCache = {};

// Initialize crypto key
let encryptionKey = null;

// Load cached data from storage
chrome.storage.local.get(['phishingCache', 'lastModelUpdate'], function(result) {
  if (result.phishingCache) {
    urlCache = result.phishingCache;
  }
  
  // Check if ML model needs updating
  const now = Date.now();
  if (!result.lastModelUpdate || (now - result.lastModelUpdate > MIN_ANALYSIS_INTERVAL)) {
    updateLocalModel();
    chrome.storage.local.set({ lastModelUpdate: now });
  }
});

// Initialize crypto key for secure operations
async function initCrypto() {
  try {
    // Check if we already have a key
    const result = await chrome.storage.local.get(['encryptionKey']);
    
    if (result.encryptionKey) {
      // Import existing key
      const keyData = base64ToArrayBuffer(result.encryptionKey);
      encryptionKey = await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    } else {
      // Generate a new key
      encryptionKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
      
      // Export and store the key
      const exportedKey = await crypto.subtle.exportKey("raw", encryptionKey);
      const keyBase64 = arrayBufferToBase64(exportedKey);
      await chrome.storage.local.set({ encryptionKey: keyBase64 });
    }
  } catch (error) {
    console.error("Crypto initialization failed:", error);
  }
}

// Helper functions for crypto operations
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Secure URL encryption
async function encryptUrl(url) {
  if (!encryptionKey) await initCrypto();
  
  try {
    // Convert string to buffer
    const encoder = new TextEncoder();
    const data = encoder.encode(url);
    
    // Encrypt
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      encryptionKey,
      data
    );
    
    // Combine IV and encrypted data
    const encryptedArray = new Uint8Array(iv.length + encryptedData.byteLength);
    encryptedArray.set(iv, 0);
    encryptedArray.set(new Uint8Array(encryptedData), iv.length);
    
    return arrayBufferToBase64(encryptedArray.buffer);
  } catch (error) {
    console.error("Encryption error:", error);
    return null;
  }
}

// Decrypt URL
async function decryptUrl(encryptedData) {
  if (!encryptionKey) await initCrypto();
  
  try {
    const data = base64ToArrayBuffer(encryptedData);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      encryptionKey,
      ciphertext
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

// Generate JWT for secure API communication
function generateJWT(secretKey) {
  // Simple JWT implementation for demo
  const header = {
    alg: "HS256",
    typ: "JWT"
  };
  
  const payload = {
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
    sub: "phishguard_extension"
  };
  
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));
  
  const signature = hmacSHA256(`${encodedHeader}.${encodedPayload}`, secretKey);
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Simplified HMAC-SHA256 for demo purposes
// In production, use a proper crypto library
function hmacSHA256(message, key) {
  // This is a placeholder for actual HMAC implementation
  return btoa(message + key).replace(/=/g, '');
}

// Update local ML model
async function updateLocalModel() {
  try {
    const requestToken = generateJWT("YOUR_SECRET_KEY");
    
    const response = await fetch(`${ML_API_ENDPOINT}/model/update`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${requestToken}`
      }
    });
    
    if (response.ok) {
      const modelData = await response.json();
      chrome.storage.local.set({ 
        modelVersion: modelData.version,
        modelParameters: modelData.parameters 
      });
      console.log("ML model updated to version:", modelData.version);
      
      // Send telemetry about model update
      sendAnonymousTelemetry("model_update", {
        version: modelData.version,
        timestamp: Date.now()
      });
    }
  } catch (error) {
    console.error("Model update failed:", error);
  }
}

// Extract URL features for ML analysis
function extractUrlFeatures(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    
    return {
      domainLength: domain.length,
      pathLength: path.length,
      queryLength: urlObj.search.length,
      fragmentLength: urlObj.hash.length,
      hasHttps: urlObj.protocol === "https:",
      portSpecified: urlObj.port !== "",
      numSubdomains: (domain.match(/\./g) || []).length,
      hasIpAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain),
      numDigits: (domain.match(/\d/g) || []).length,
      numSpecialChars: (domain.match(/[^a-zA-Z0-9.]/g) || []).length,
      tldLength: domain.split('.').pop().length,
      hasUrlShortener: isUrlShortener(domain),
      domainAge: -1, // Will be populated by API if available
      hasSuspiciousKeywords: checkSuspiciousKeywords(url),
      hasExcessiveSubdomains: (domain.match(/\./g) || []).length > 3,
      pathDepth: (path.match(/\//g) || []).length,
      hasMultipleRedirects: url.includes("redirect") || url.includes("url="),
      usesSuspiciousTld: checkSuspiciousTld(domain)
    };
  } catch (error) {
    console.error("Feature extraction error:", error);
    return {};
  }
}

// Check for URL shortening services
function isUrlShortener(domain) {
  const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];
  return shorteners.some(shortener => domain.includes(shortener));
}

// Check for suspicious keywords
function checkSuspiciousKeywords(url) {
  const keywords = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password", "bank"];
  const urlLower = url.toLowerCase();
  return keywords.some(keyword => urlLower.includes(keyword));
}

// Check for suspicious TLDs
function checkSuspiciousTld(domain) {
  const suspiciousTlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".date", ".loan"];
  return suspiciousTlds.some(tld => domain.endsWith(tld));
}

// Request ML-based analysis from API
async function requestMlAnalysis(url) {
  const requestToken = generateJWT("YOUR_SECRET_KEY");
  const encryptedUrl = await encryptUrl(url);
  const features = extractUrlFeatures(url);
  
  try {
    const response = await fetch(ML_API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${requestToken}`
      },
      body: JSON.stringify({
        url: encryptedUrl,
        features: features
      })
    });
    
    if (!response.ok) {
      throw new Error('ML API request failed');
    }
    
    const result = await response.json();
    return {
      isSafe: result.phishing_probability < 0.7,
      confidence: result.confidence,
      phishingProbability: result.phishing_probability,
      reasons: result.reasons || []
    };
  } catch (error) {
    console.error("ML analysis error:", error);
    // Fail closed - if ML check fails, don't assume safe
    return { 
      isSafe: false, 
      confidence: 0, 
      phishingProbability: 0.5,
      reasons: ["ML analysis service unavailable"] 
    };
  }
}

// Check against known phishing domains
function checkAgainstKnownPhishing(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Direct match check
    const directMatch = KNOWN_PHISHING_DOMAINS.includes(domain);
    
    // Substring match check (for subdomains)
    const substringMatch = KNOWN_PHISHING_DOMAINS.some(knownDomain => 
      domain.includes(knownDomain) || knownDomain.includes(domain));
    
    return {
      isBlocked: directMatch || substringMatch,
      reason: directMatch ? "Known phishing domain" : 
              substringMatch ? "Similar to known phishing domain" : ""
    };
  } catch (error) {
    console.error("Domain check error:", error);
    return { isBlocked: false, reason: "" };
  }
}

// Calculate phishing score based on URL characteristics
function calculatePhishingScore(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    let score = 0;
    let reasons = [];
    
    // Check for misspellings of popular domains
    const popularDomains = ["google", "facebook", "amazon", "apple", "microsoft", "paypal", "chase", "bankofamerica"];
    for (const popularDomain of popularDomains) {
      if (domain.includes(popularDomain) && domain !== `${popularDomain}.com`) {
        score += 0.4;
        reasons.push(`Similar to ${popularDomain}.com but not exact match`);
        break;
      }
    }
    
    // Check for excessive subdomains
    if ((domain.match(/\./g) || []).length > 3) {
      score += 0.2;
      reasons.push("Excessive number of subdomains");
    }
    
    // Check for suspicious TLDs
    const suspiciousTLDs = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top"];
    for (const tld of suspiciousTLDs) {
      if (domain.endsWith(tld)) {
        score += 0.3;
        reasons.push(`Uses suspicious TLD: ${tld}`);
        break;
      }
    }
    
    // Check for numbers replacing letters
    if (/\d/.test(domain)) {
      score += 0.2;
      reasons.push("Contains numbers potentially replacing letters");
    }
    
    // Check for security-related keywords in URL
    const securityKeywords = ["secure", "login", "verify", "account", "update", "confirm", "password"];
    for (const keyword of securityKeywords) {
      if (url.toLowerCase().includes(keyword)) {
        score += 0.1;
        reasons.push(`Contains security keyword: ${keyword}`);
      }
    }
    
    // Check for random strings in domain
    if (/[a-z0-9]{10,}/.test(domain)) {
      score += 0.3;
      reasons.push("Contains random-looking string");
    }
    
    // Check for IP address in URL
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
      score += 0.5;
      reasons.push("Uses IP address instead of domain name");
    }
    
    // Check if URL has unusual port
    if (urlObj.port && urlObj.port !== "80" && urlObj.port !== "443") {
      score += 0.3;
      reasons.push(`Uses unusual port: ${urlObj.port}`);
    }
    
    // Check for URL shorteners
    const urlShorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"];
    for (const shortener of urlShorteners) {
      if (domain.includes(shortener)) {
        score += 0.2;
        reasons.push("Uses URL shortening service");
        break;
      }
    }
    
    // Check for HTTP instead of HTTPS
    if (urlObj.protocol === "http:") {
      score += 0.3;
      reasons.push("Uses insecure HTTP protocol");
    }
    
    // Normalize score to be between 0 and 1
    return {
      score: Math.min(score, 1),
      reasons: reasons
    };
  } catch (error) {
    console.error("Score calculation error:", error);
    return { score: 0.5, reasons: ["Error analyzing URL"] };
  }
}

// Calculate aggregate risk score from multiple verification methods
function calculateAggregateRiskScore(verificationResults) {
  // Weight the different methods
  const weights = {
    "pattern": 0.3,
    "blocklist": 0.3,
    "ml": 0.4
  };
  
  let weightedScoreSum = 0;
  let weightSum = 0;
  
  verificationResults.forEach(result => {
    const method = result.method;
    const weight = weights[method] || 0.2; // Default weight
    
    // Invert the result for scoring (true means safe, so low risk)
    const riskContribution = result.result ? 0 : 1;
    
    weightedScoreSum += riskContribution * weight;
    weightSum += weight;
  });
  
  // Normalize by weights
  return weightSum > 0 ? weightedScoreSum / weightSum : 0.5;
}

// Implement Zero Trust for URL analysis
async function checkPhishingUrl(url) {
  try {
    // Parse the URL to get domain
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Check cache first
    if (urlCache[domain]) {
      // Only use cache if not expired (15 minutes)
      const now = Date.now();
      if (now - urlCache[domain].timestamp < 900000) {
        return urlCache[domain].data;
      }
    }
    
    // Multiple verification layers (Zero Trust approach)
    let verificationResults = [];
    
    // Layer 1: Local pattern analysis
    const patternAnalysis = calculatePhishingScore(url);
    verificationResults.push({
      method: "pattern",
      result: patternAnalysis.score < 0.6,
      details: patternAnalysis
    });
    
    // Layer 2: Blocklist verification
    const knownPhishingCheck = checkAgainstKnownPhishing(url);
    verificationResults.push({
      method: "blocklist",
      result: !knownPhishingCheck.isBlocked,
      details: knownPhishingCheck
    });
    
    // Layer 3: ML-based analysis (if available)
    try {
      const mlAnalysis = await requestMlAnalysis(url);
      verificationResults.push({
        method: "ml",
        result: mlAnalysis.isSafe,
        details: mlAnalysis
      });
    } catch (error) {
      console.error("ML analysis unavailable:", error);
      // Don't count this as safe if ML check fails
    }
    
    // URL is considered safe only if ALL verification methods agree
    const isSafe = verificationResults.every(check => check.result === true);
    
    // Calculate risk score
    const riskScore = calculateAggregateRiskScore(verificationResults);
    
    // Collect reasons from all verification methods
    const allReasons = verificationResults.flatMap(check => 
      check.details?.reasons || []);
    
    // Result object
    const result = {
      isSafe: isSafe,
      isPishing: !isSafe, // For compatibility with original code
      riskScore: riskScore,
      verificationResults: verificationResults,
      reasons: [...new Set(allReasons)], // Remove duplicates
      timestamp: Date.now()
    };
    
    // Update cache
    urlCache[domain] = {
      data: result,
      timestamp: Date.now()
    };
    
    // Update storage
    chrome.storage.local.set({ phishingCache: urlCache });
    
    // Send telemetry if enabled
    sendAnonymousTelemetry("url_check", {
      isSafe: isSafe,
      riskScore: riskScore,
      methodsCount: verificationResults.length
    });
    
    return result;
  } catch (error) {
    console.error("Error checking phishing URL:", error);
    // Fail closed - if check fails, treat as unsafe
    return { 
      isSafe: false, 
      isPishing: true, 
      riskScore: 0.7,
      reasons: ["Error analyzing URL"]
    };
  }
}

// Telemetry module - only send anonymous data if opted in
async function sendAnonymousTelemetry(eventType, metadata) {
  try {
    const settings = await chrome.storage.sync.get(TELEMETRY_SETTINGS_KEY);
    if (!settings[TELEMETRY_SETTINGS_KEY]?.optIn) return;
    
    // Generate anonymous installation ID if not exists
    let installId = settings[TELEMETRY_SETTINGS_KEY]?.installId;
    if (!installId) {
      installId = crypto.randomUUID();
      await chrome.storage.sync.set({
        [TELEMETRY_SETTINGS_KEY]: {
          ...settings[TELEMETRY_SETTINGS_KEY],
          installId
        }
      });
    }
    
    // Sanitize data to remove any PII
    const sanitizedMetadata = sanitizeTelemetryData(metadata);
    
    // Send anonymous data
    await fetch(TELEMETRY_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        installId,
        eventType,
        timestamp: Date.now(),
        extensionVersion: chrome.runtime.getManifest().version,
        metadata: sanitizedMetadata
      })
    });
  } catch (error) {
    console.error("Telemetry error:", error);
  }
}

// Remove any potentially identifying information
function sanitizeTelemetryData(metadata) {
  const sanitized = { ...metadata };
  
  // Remove any URLs or domains
  delete sanitized.url;
  delete sanitized.domain;
  
  // Remove any user identifiers
  delete sanitized.userId;
  delete sanitized.email;
  delete sanitized.username;
  
  return sanitized;
}

// Listen for web navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only check main frame navigations
  if (details.frameId === 0) {
    const result = await checkPhishingUrl(details.url);
    if (!result.isSafe && result.riskScore > 0.7) {
      // High risk - Alert user about potential phishing site
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(details.url)
      });
    } else if (!result.isSafe && result.riskScore > 0.4) {
      // Medium risk - Show warning banner but allow continuing
      chrome.tabs.sendMessage(details.tabId, {
        action: "showWarningBanner",
        url: details.url,
        assessment: result
      });
    }
  }
});

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkUrl") {
    checkPhishingUrl(message.url).then(result => {
      sendResponse(result);
    });
    return true; // Required for async sendResponse
  }
  
  if (message.action === "getStats") {
    const stats = {
      urlsChecked: Object.keys(urlCache).length,
      phishingDetected: Object.values(urlCache)
        .filter(v => !v.data.isSafe).length,
      lastUpdated: new Date().toLocaleString()
    };
    sendResponse(stats);
    return true;
  }
  
  if (message.action === "setTelemetrySettings") {
    chrome.storage.sync.set({
      [TELEMETRY_SETTINGS_KEY]: message.settings
    }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// Initialize crypto on extension startup
initCrypto();