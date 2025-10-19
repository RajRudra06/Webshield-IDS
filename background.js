// initialisation (installation by user)

chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
      console.log('🎉 WebShield installed!');
      
      // Create a unique user ID
      const userId = 'user_' + Date.now();
      
      // Save initial data to Chrome's storage
      chrome.storage.local.set({
        userId: userId,
        stats: {
          blocked: 0,    // How many threats blocked
          scanned: 0,    // How many URLs checked
          safe: 0        // How many were safe
        },
        threatDatabase: []  // List of known bad URLs
      });
      
      console.log('✅ Extension initialized with user ID:', userId);
    }
  });
  
//  url interception, runs at each url
  
  chrome.webRequest.onBeforeRequest.addListener(
    async function(details) {
      // Only check main page loads (not images, scripts, etc.)
      if (details.type !== 'main_frame') {
        return { cancel: false };  // Allow it
      }
      
      const url = details.url;
      console.log('🔍 Checking URL:', url);
      
      // Step 1: Quick check against known threats
      const isKnownThreat = await checkLocalDatabase(url);
      if (isKnownThreat) {
        console.log('🚫 BLOCKED - Known threat!');
        blockURL(details.tabId, url, 'This URL is in our threat database');
        updateStats('blocked');
        return { cancel: true };  // BLOCK IT!
      }
      
      // Step 2: Heuristic check (pattern matching)
      const suspicionScore = quickHeuristicCheck(url);
      console.log('🎯 Suspicion score:', suspicionScore);
      
      if (suspicionScore > 0.7) {
        console.log('🚫 BLOCKED - Suspicious patterns detected!');
        blockURL(details.tabId, url, 'URL contains suspicious patterns');
        updateStats('blocked');
        return { cancel: true };  // BLOCK IT!
      }
      
      // Step 3: Send to backend for ML analysis
      console.log('📤 Sending to ML model for analysis...');
      analyzeWithBackend(url, details.tabId);
      updateStats('scanned');
      
      // Allow page to load (analysis happens in background)
      return { cancel: false };
    },
    { urls: ["<all_urls>"] },  // Monitor ALL URLs
    ["blocking"]                // Allow blocking requests
  );
  
// helper func - local databases (1)
  
  async function checkLocalDatabase(url) {
    // Get our saved threat list
    const data = await chrome.storage.local.get('threatDatabase');
    const threats = data.threatDatabase || [];
    
    // Extract domain from URL
    const domain = extractDomain(url);
    
    // Check if URL or domain is in threat list
    for (let threat of threats) {
      if (url.includes(threat) || domain.includes(threat)) {
        return true;  // It's a known threat!
      }
    }
    
    return false;  // Not in database
  }
  
//   helper func - heuristic search 
  
  function quickHeuristicCheck(url) {
    let score = 0;
    
    // ip or not ?
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 0.3;
      console.log('  ⚠️ Contains IP address (+0.3)');
    }
    
    // suspicious domain
    if (/\.(tk|ml|ga|cf|gq|pw)$/i.test(url)) {
      score += 0.3;
      console.log('  ⚠️ Suspicious TLD (+0.3)');
    }
    
    // @ directive exist or not ?
    if (url.includes('@')) {
      score += 0.4;
      console.log('  ⚠️ Contains @ symbol (+0.4)');
    }
    
    // multiple susdomains exist ?
    const domain = extractDomain(url);
    const dotCount = (domain.match(/\./g) || []).length;
    if (dotCount > 3) {
      score += 0.2;
      console.log('  ⚠️ Too many subdomains (+0.2)');
    }
    
    // phishing domains/keywords
    if (/verify|secure|account|update|confirm|login|signin/i.test(domain)) {
      score += 0.2;
      console.log('  ⚠️ Phishing keywords in domain (+0.2)');
    }
    
    // long urls?
    if (url.length > 100) {
      score += 0.15;
      console.log('  ⚠️ Very long URL (+0.15)');
    }
    
    // http? should be https
    if (url.startsWith('http://') && !url.startsWith('http://localhost')) {
      score += 0.1;
      console.log('  ⚠️ No HTTPS (+0.1)');
    }
    
    // Cap score at 1.0 (100%)
    return Math.min(score, 1.0);
  }
  
// helper func - domain extraction
  
  function extractDomain(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname;  // Returns "google.com" from "https://google.com/search"
    } catch (error) {
      return url;  // If parsing fails, return original
    }
  }
  
// helper func - blockURL
  
  function blockURL(tabId, url, reason) {
    // Create warning page URL with parameters
    const blockedURL = chrome.runtime.getURL('blocked.html') + 
      '?url=' + encodeURIComponent(url) + 
      '&reason=' + encodeURIComponent(reason);
    
    // Redirect the tab to our warning page
    chrome.tabs.update(tabId, { url: blockedURL });
    
    // Show desktop notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icon.png',
      title: '🛡️ Threat Blocked!',
      message: `Blocked malicious site: ${extractDomain(url)}`
    });
    
    console.log('🛡️ User protected! Redirected to warning page.');
  }
  
//   update stats
  
  async function updateStats(type) {
    // Get current stats
    const data = await chrome.storage.local.get('stats');
    const stats = data.stats || { blocked: 0, scanned: 0, safe: 0 };
    
    // Increment the counter
    stats[type]++;
    
    // Save back to storage
    await chrome.storage.local.set({ stats });
    
    // Update badge on extension icon
    if (type === 'blocked') {
      chrome.action.setBadgeText({ text: stats.blocked.toString() });
      chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
    }
    
    console.log('📊 Stats updated:', stats);
  }
// helper func - send backend ML req
  
  async function analyzeWithBackend(url, tabId) {
    try {
      // Extract features from URL
      const features = extractURLFeatures(url);
      
      // Get user ID
      const data = await chrome.storage.local.get('userId');
      const userId = data.userId || 'anonymous';
      
      console.log('📡 Sending to backend:', features);
      
      // Call backend API
      const response = await fetch('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: url,
          features: features,
          userId: userId
        })
      });
      
      const result = await response.json();
      console.log('📥 ML Result:', result);
      
      // If ML model says it's phishing with high confidence
      if (result.isPhishing && result.confidence > 0.6) {
        console.log('🚨 ML DETECTED PHISHING!');
        
        // Block it (even though page already loaded)
        blockURL(tabId, url, `ML model detected phishing (${(result.confidence * 100).toFixed(0)}% confidence)`);
        updateStats('blocked');
        
        // Close the tab
        chrome.tabs.remove(tabId);
      } else {
        console.log('✅ ML says it\'s safe');
        updateStats('safe');
      }
      
    } catch (error) {
      console.error('❌ Backend analysis failed:', error);
      // Fail open - if backend is down, allow access
    }
  }
  
//  feature extraction from url
  
  function extractURLFeatures(url) {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname;
      
      return {
        // Length features
        url_length: url.length,
        domain_length: domain.length,
        path_length: parsed.pathname.length,
        
        // Pattern features (1 = yes, 0 = no)
        has_ip: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) ? 1 : 0,
        subdomain_count: (domain.match(/\./g) || []).length - 1,
        has_at: url.includes('@') ? 1 : 0,
        has_double_slash: (url.match(/\/\//g) || []).length > 1 ? 1 : 0,
        special_chars: (url.match(/[^a-zA-Z0-9]/g) || []).length,
        is_https: parsed.protocol === 'https:' ? 1 : 0,
        suspicious_tld: /\.(tk|ml|ga|cf|gq)$/i.test(domain) ? 1 : 0,
        has_suspicious_words: /verify|secure|account|update|confirm/i.test(domain) ? 1 : 0
      };
    } catch (error) {
      console.error('Error extracting features:', error);
      return null;
    }
  }
  
  console.log('🛡️ WebShield IDS background script loaded!');