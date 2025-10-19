// Load stats on popup open
document.addEventListener('DOMContentLoaded', loadStats);

async function loadStats() {
  const data = await chrome.storage.local.get('stats');
  const stats = data.stats || { blocked: 0, scanned: 0, safe: 0 };
  
  document.getElementById('blocked').textContent = stats.blocked;
  document.getElementById('scanned').textContent = stats.scanned;
  document.getElementById('safe').textContent = stats.safe;
}

// Refresh button
document.getElementById('refresh').addEventListener('click', loadStats);

// Dashboard button
document.getElementById('dashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://localhost:5173' }); // Vite dev server
});