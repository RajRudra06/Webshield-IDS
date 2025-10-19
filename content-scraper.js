// ==================================================
// Content Script - Runs ON every webpage
// This can see and interact with page content
// ==================================================

console.log('🛡️ WebShield scanning page:', window.location.href);

// ==================================================
// SCAN 1: Check for Insecure Forms (HTTP)
// ==================================================

// Wait for page to load
window.addEventListener('load', () => {
  console.log('📄 Page loaded, starting content scan...');
  
  // Find all forms on the page
  const forms = document.querySelectorAll('form');
  console.log(`Found ${forms.length} forms`);
  
  forms.forEach((form, index) => {
    // Check if form submits to HTTP (not HTTPS)
    const formAction = form.action || window.location.href;
    
    if (formAction.startsWith('http://') && !formAction.includes('localhost')) {
      console.warn(`⚠️ INSECURE FORM #${index + 1}:`, formAction);
      
      // Highlight the form in red
      form.style.border = '3px solid red';
      form.style.backgroundColor = '#fff3cd';
      
      // Add warning message
      const warning = document.createElement('div');
      warning.innerHTML = '⚠️ WARNING: This form is not secure (HTTP)';
      warning.style.cssText = `
        background: #dc3545;
        color: white;
        padding: 10px;
        font-weight: bold;
        text-align: center;
        margin-bottom: 10px;
      `;
      form.insertBefore(warning, form.firstChild);
      
      // Intercept form submission
      form.addEventListener('submit', (e) => {
        const confirmed = confirm(
          '⚠️ SECURITY WARNING!\n\n' +
          'This form is not secure (HTTP).\n' +
          'Your data could be intercepted by attackers.\n\n' +
          'Do you want to continue anyway?'
        );
        
        if (!confirmed) {
          e.preventDefault();
          console.log('✅ User chose not to submit insecure form');
          
          // Report to extension
          chrome.runtime.sendMessage({
            type: 'INSECURE_FORM_BLOCKED',
            url: window.location.href,
            formAction: formAction
          });
        }
      });
    }
  });
});

// ==================================================
// SCAN 2: Detect Password Fields
// ==================================================

window.addEventListener('load', () => {
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  if (passwordFields.length > 0) {
    console.log(`🔒 Found ${passwordFields.length} password fields`);
    
    // Check if this is a trusted domain
    const domain = window.location.hostname;
    const trustedDomains = [
      'google.com',
      'facebook.com',
      'github.com',
      'microsoft.com',
      'apple.com',
      'amazon.com'
    ];
    
    const isTrusted = trustedDomains.some(trusted => domain.includes(trusted));
    
    if (!isTrusted) {
      console.warn('⚠️ Unknown site asking for password!');
      
      // Monitor password field
      passwordFields.forEach(field => {
        field.addEventListener('focus', () => {
          // Notify user first time they focus password field
          if (!field.dataset.warned) {
            field.dataset.warned = 'true';
            
            // Show subtle warning
            const warning = document.createElement('div');
            warning.textContent = '🛡️ WebShield: Make sure this is a legitimate site before entering password';
            warning.style.cssText = `
              position: fixed;
              top: 20px;
              right: 20px;
              background: #ffc107;
              color: #333;
              padding: 15px;
              border-radius: 5px;
              box-shadow: 0 4px 12px rgba(0,0,0,0.3);
              z-index: 999999;
              max-width: 300px;
              font-weight: bold;
            `;
            document.body.appendChild(warning);
            
            setTimeout(() => warning.remove(), 5000);
          }
        });
      });
    }
  }
});

// ==================================================
// SCAN 3: Check for Suspicious Scripts
// ==================================================

window.addEventListener('load', () => {
  const scripts = document.querySelectorAll('script[src]');
  console.log(`📜 Found ${scripts.length} external scripts`);
  
  // Known crypto-mining domains
  const cryptoMinerDomains = [
    'coinhive.com',
    'crypto-loot.com',
    'coin-hive.com',
    'webminer.pro',
    'monerominer.rocks',
    'jsecoin.com'
  ];
  
  scripts.forEach(script => {
    const src = script.src;
    
    // Check if script is from known crypto-miner domain
    const isMiner = cryptoMinerDomains.some(domain => src.includes(domain));
    
    if (isMiner) {
      console.warn('🚨 CRYPTO MINER DETECTED:', src);
      
      // Remove the script
      script.remove();
      
      // Show banner to user
      showBanner('🛡️ WebShield blocked a crypto-mining script!', '#28a745');
      
      // Report to extension
      chrome.runtime.sendMessage({
        type: 'CRYPTO_MINER_BLOCKED',
        url: window.location.href,
        minerScript: src
      });
    }
  });
});

// ==================================================
// SCAN 4: Monitor for Suspicious Redirects
// ==================================================

let redirectCount = 0;
const originalPushState = history.pushState;

// Override history.pushState to detect rapid redirects
history.pushState = function() {
  redirectCount++;
  
  if (redirectCount > 3) {
    console.warn('⚠️ SUSPICIOUS: Multiple rapid redirects detected');
    
    chrome.runtime.sendMessage({
      type: 'SUSPICIOUS_REDIRECT',
      url: window.location.href,
      redirectCount: redirectCount
    });
    
    showBanner('⚠️ This site is redirecting multiple times. Be cautious!', '#ffc107');
  }
  
  return originalPushState.apply(this, arguments);
};

// ==================================================
// SCAN 5: Check URL Parameters for XSS
// ==================================================

window.addEventListener('load', () => {
  const urlParams = new URLSearchParams(window.location.search);
  
  urlParams.forEach((value, key) => {
    // Check for dangerous patterns in URL parameters
    const dangerousPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror=/i,
      /onload=/i,
      /<iframe/i,
      /eval\(/i
    ];
    
    const isDangerous = dangerousPatterns.some(pattern => pattern.test(value));
    
    if (isDangerous) {
      console.error('🚨 POSSIBLE XSS ATTACK in URL parameter:', key, '=', value);
      
      chrome.runtime.sendMessage({
        type: 'XSS_ATTEMPT',
        url: window.location.href,
        param: key,
        value: value
      });
      
      showBanner('🚨 Possible attack detected in URL! Be careful!', '#dc3545');
    }
  });
});

// ==================================================
// HELPER: Show Banner to User
// ==================================================

function showBanner(message, color) {
  const banner = document.createElement('div');
  banner.textContent = message;
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: ${color};
    color: white;
    padding: 15px;
    text-align: center;
    font-size: 16px;
    font-weight: bold;
    z-index: 999999;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    animation: slideDown 0.5s ease;
  `;
  
  document.body.appendChild(banner);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    banner.style.animation = 'slideUp 0.5s ease';
    setTimeout(() => banner.remove(), 500);
  }, 5000);
}

// ==================================================
// Listen for Messages from Background Script
// ==================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📨 Received message:', message.type);
  
  if (message.type === 'SHOW_WARNING_BANNER') {
    showBanner(message.text, '#dc3545');
  }
  
  sendResponse({ received: true });
});

// ==================================================
// DONE!
// This content script now:
// 1. Scans for insecure forms
// 2. Warns about password fields on unknown sites
// 3. Blocks crypto-mining scripts
// 4. Detects suspicious redirects
// 5. Checks for XSS attacks
// ==================================================

console.log('✅ WebShield content scanner ready!');