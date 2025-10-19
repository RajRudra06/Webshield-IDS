// ==================================================
// blocked.js - Warning Page Logic
// ==================================================

console.log('⚠️ Blocked page loaded');

// Get URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url');
const reason = params.get('reason');

console.log('Blocked URL:', blockedUrl);
console.log('Reason:', reason);

// ==================================================
// POPULATE PAGE CONTENT
// ==================================================

// Display URL
document.getElementById('blocked-url').textContent = blockedUrl || 'Unknown URL';

// Display reason
document.getElementById('reason').textContent = reason || 'This site contains malicious content';

// Determine threat type based on reason
let threatType = 'Phishing / Malware';
if (reason && reason.toLowerCase().includes('phishing')) {
  threatType = 'Phishing Attempt';
} else if (reason && reason.toLowerCase().includes('malware')) {
  threatType = 'Malware Distribution';
} else if (reason && reason.toLowerCase().includes('suspicious')) {
  threatType = 'Suspicious Activity';
} else if (reason && reason.toLowerCase().includes('ip address')) {
  threatType = 'Suspicious IP-based URL';
} else if (reason && reason.toLowerCase().includes('ml')) {
  threatType = 'Machine Learning Detection';
}

document.getElementById('threat-type').textContent = threatType;

// ==================================================
// BUTTON: Go Back to Safety
// ==================================================

function goBack() {
  console.log('User clicked: Go Back');
  
  // Try to go back in history
  if (window.history.length > 1) {
    window.history.back();
  } else {
    // If no history, go to safe page
    window.location.href = 'https://google.com';
  }
}

// ==================================================
// BUTTON: Proceed Anyway (Dangerous!)
// ==================================================

function proceedAnyway() {
  console.log('User clicked: Proceed Anyway');
  
  // Show strong warning
  const confirmed = confirm(
    '⚠️⚠️⚠️ FINAL WARNING ⚠️⚠️⚠️\n\n' +
    'This website has been identified as DANGEROUS.\n\n' +
    'Visiting this site may result in:\n' +
    '• Theft of your passwords and personal data\n' +
    '• Financial fraud\n' +
    '• Malware infection\n' +
    '• Identity theft\n\n' +
    'Are you ABSOLUTELY SURE you want to continue?'
  );
  
  if (!confirmed) {
    console.log('User cancelled');
    return;
  }
  
  // Second confirmation (extra safety)
  const doubleConfirmed = confirm(
    'Last chance!\n\n' +
    'By clicking OK, you acknowledge that:\n' +
    '• You understand the risks\n' +
    '• WebShield IDS is not responsible for any damage\n' +
    '• You are proceeding at your own risk\n\n' +
    'Continue to dangerous site?'
  );
  
  if (doubleConfirmed) {
    console.log('User force-proceeded to dangerous site');
    
    // Log this action
    if (chrome && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'USER_FORCE_PROCEEDED',
        url: blockedUrl,
        timestamp: Date.now()
      });
    }
    
    // Redirect to the dangerous URL
    window.location.href = blockedUrl;
  } else {
    console.log('User changed mind (good!)');
    
    // Show encouragement
    alert('✅ Good choice! Your security is important.');
  }
}

// ==================================================
// AUTO-UPDATE PAGE TITLE
// ==================================================

document.title = '🚫 Threat Blocked - WebShield IDS';

// ==================================================
// KEYBOARD SHORTCUTS
// ==================================================

document.addEventListener('keydown', (e) => {
  // Press ESC or Backspace to go back
  if (e.key === 'Escape' || e.key === 'Backspace') {
    e.preventDefault();
    goBack();
  }
});

// ==================================================
// ANALYTICS: Track how long user stays on warning page
// ==================================================

const arrivalTime = Date.now();

window.addEventListener('beforeunload', () => {
  const timeSpent = Date.now() - arrivalTime;
  console.log(`User spent ${(timeSpent / 1000).toFixed(1)}s on warning page`);
  
  // Send analytics to background script
  if (chrome && chrome.runtime) {
    chrome.runtime.sendMessage({
      type: 'WARNING_PAGE_ANALYTICS',
      url: blockedUrl,
      timeSpent: timeSpent
    });
  }
});

// ==================================================
// SHOW ADDITIONAL WARNINGS FOR SPECIFIC THREATS
// ==================================================

if (blockedUrl) {
  // Check for specific threat indicators
  const domain = blockedUrl.split('/')[2] || '';
  
  // Banking-related phishing
  if (domain.includes('paypal') || domain.includes('bank') || domain.includes('account')) {
    const extraWarning = document.createElement('div');
    extraWarning.style.cssText = `
      background: #dc3545;
      color: white;
      padding: 15px;
      margin-top: 20px;
      border-radius: 8px;
      text-align: center;
      font-weight: bold;
    `;
    extraWarning.innerHTML = '🏦 BANKING SCAM DETECTED<br>This site is attempting to steal your financial credentials!';
    document.querySelector('.warning-box').appendChild(extraWarning);
  }
  
  // Crypto-related scams
  if (domain.includes('crypto') || domain.includes('bitcoin') || domain.includes('wallet')) {
    const extraWarning = document.createElement('div');
    extraWarning.style.cssText = `
      background: #dc3545;
      color: white;
      padding: 15px;
      margin-top: 20px;
      border-radius: 8px;
      text-align: center;
      font-weight: bold;
    `;
    extraWarning.innerHTML = '₿ CRYPTO SCAM DETECTED<br>This site may steal your cryptocurrency!';
    document.querySelector('.warning-box').appendChild(extraWarning);
  }
}

// ==================================================
// DONE!
// Warning page now:
// 1. Displays blocked URL and reason
// 2. Provides safe "go back" option
// 3. Warns strongly if user tries to proceed
// 4. Tracks analytics
// 5. Shows extra warnings for specific threats
// ==================================================

console.log('✅ Blocked page script loaded!');