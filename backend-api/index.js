const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { PythonShell } = require('python-shell');

const app = express();
const PORT = 3000;

require('dotenv').config();
const path = require('path');

// At the top of your file
const PYTHON_SCRIPT_PATH = process.env.PYTHON_SCRIPT_PATH || 
  path.join(__dirname, '../pythonProject/predict-system.py');

const PYTHON_PATH = process.env.PYTHON_PATH || 'python3';

console.log('🐍 Using Python:', PYTHON_PATH);
console.log('📄 Using Script:', PYTHON_SCRIPT_PATH);

app.use(cors());
app.use(bodyParser.json());

// In-memory storage (for MVP - use MongoDB in production)
const threats = [];
const urlHistory = [];

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'WebShield Backend Running', version: '1.0.0' });
});

// Analyze URL with ML model
app.post('/api/analyze', async (req, res) => {
  try {
    const { url, features, userId } = req.body;
    
    console.log('🔍 Analyzing:', url);
    console.log('📊 Features:', JSON.stringify(features));
    
    // Call Python ML model
    const options = {
      mode: 'text',  // Changed from 'json' to 'text'
      pythonPath: PYTHON_PATH,
      pythonOptions: ['-u'],
      args: [JSON.stringify(features)]
    };
    
    console.log('🚀 Running Python with options:', options);
    
    PythonShell.run(PYTHON_SCRIPT_PATH, options, (err, results) => {
      if (err) {
        console.error('❌ ML Error:', err);
        return res.json({
          isPhishing: false,
          confidence: 0,
          error: 'Model unavailable'
        });
      }
      
      console.log('📥 Raw Results:', results);
      
      // Parse the JSON output from the last line
      let prediction;
      try {
        const lastLine = results[results.length - 1];
        prediction = JSON.parse(lastLine);
        console.log('✅ Parsed prediction:', prediction);
      } catch (parseErr) {
        console.error('❌ JSON Parse Error:', parseErr);
        return res.json({
          isPhishing: false,
          confidence: 0,
          error: 'Failed to parse prediction'
        });
      }
      
      // Log to history
      urlHistory.push({
        url,
        userId,
        timestamp: new Date(),
        prediction
      });
      
      // If threat detected, add to threats list
      if (prediction.isPhishing && prediction.confidence > 0.6) {
        threats.push({
          url,
          userId,
          type: 'phishing',
          confidence: prediction.confidence,
          timestamp: new Date()
        });
      }
      
      console.log('✅ Sending response:', prediction);
      res.json(prediction);
    });
    
  } catch (error) {
    console.error('💥 Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// Get user stats
app.get('/api/stats/:userId', (req, res) => {
  const { userId } = req.params;
  
  const userThreats = threats.filter(t => t.userId === userId);
  const userHistory = urlHistory.filter(h => h.userId === userId);
  
  res.json({
    totalScanned: userHistory.length,
    threatsBlocked: userThreats.length,
    safeURLs: userHistory.length - userThreats.length,
    recentThreats: userThreats.slice(-5)
  });
});

// Get all threats (for dashboard)
app.get('/api/threats', (req, res) => {
  res.json({
    total: threats.length,
    recent: threats.slice(-10).reverse()
  });
});

// Get URL history
app.get('/api/history/:userId', (req, res) => {
  const { userId } = req.params;
  const userHistory = urlHistory
    .filter(h => h.userId === userId)
    .slice(-20)
    .reverse();
  
  res.json(userHistory);
});

app.listen(PORT, () => {
  console.log(`🚀 WebShield Backend running on http://localhost:${PORT}`);
});