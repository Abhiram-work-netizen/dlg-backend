require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ──────────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// ─── File Upload Config ──────────────────────────────────────
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
});

// ─── Threat Intelligence APIs ────────────────────────────────
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const GSB_API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || '';

// ─── Link Scanner ────────────────────────────────────────────
app.post('/scan/link', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const results = {
      url,
      timestamp: new Date().toISOString(),
      checks: [],
      riskLevel: 'LOW',
      riskScore: 0,
    };

    // 1. Local Heuristics
    const localCheck = runLocalHeuristics(url);
    results.checks.push({ source: 'Local Heuristics', ...localCheck });
    results.riskScore += localCheck.score;

    // 2. VirusTotal (if API key is set)
    if (VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here') {
      try {
        const vtResult = await scanWithVirusTotal(url);
        results.checks.push({ source: 'VirusTotal', ...vtResult });
        results.riskScore += vtResult.score;
      } catch (e) {
        results.checks.push({ source: 'VirusTotal', status: 'unavailable', detail: e.message, score: 0 });
      }
    }

    // 3. Google Safe Browsing (if API key is set)
    if (GSB_API_KEY && GSB_API_KEY !== 'your_google_safe_browsing_key_here') {
      try {
        const gsbResult = await scanWithGoogleSafeBrowsing(url);
        results.checks.push({ source: 'Google Safe Browsing', ...gsbResult });
        results.riskScore += gsbResult.score;
      } catch (e) {
        results.checks.push({ source: 'Google Safe Browsing', status: 'unavailable', detail: e.message, score: 0 });
      }
    }

    // Determine risk level
    if (results.riskScore >= 70) results.riskLevel = 'HIGH';
    else if (results.riskScore >= 40) results.riskLevel = 'MEDIUM';
    else results.riskLevel = 'LOW';

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', detail: error.message });
  }
});

// ─── File Scanner ────────────────────────────────────────────
app.post('/scan/file', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File is required' });

  try {
    const fs = require('fs');
    const fileBuffer = fs.readFileSync(req.file.path);
    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    const results = {
      filename: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
      sha256: fileHash,
      timestamp: new Date().toISOString(),
      checks: [],
      riskLevel: 'LOW',
      riskScore: 0,
    };

    // Local file heuristics
    const ext = path.extname(req.file.originalname).toLowerCase();
    const dangerousExts = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.vbs', '.js', '.jar', '.apk'];
    if (dangerousExts.includes(ext)) {
      results.checks.push({
        source: 'File Type Analysis',
        status: 'warning',
        detail: `Potentially dangerous file type: ${ext}`,
        score: 60,
      });
      results.riskScore += 60;
    } else {
      results.checks.push({
        source: 'File Type Analysis',
        status: 'safe',
        detail: `File type ${ext || 'unknown'} is generally safe`,
        score: 0,
      });
    }

    // VirusTotal file hash lookup
    if (VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here') {
      try {
        const vtResult = await checkFileHashVirusTotal(fileHash);
        results.checks.push({ source: 'VirusTotal Hash', ...vtResult });
        results.riskScore += vtResult.score;
      } catch (e) {
        results.checks.push({ source: 'VirusTotal Hash', status: 'unavailable', detail: e.message, score: 0 });
      }
    }

    // Determine risk level
    if (results.riskScore >= 70) results.riskLevel = 'HIGH';
    else if (results.riskScore >= 40) results.riskLevel = 'MEDIUM';
    else results.riskLevel = 'LOW';

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'File scan failed', detail: error.message });
  }
});

// ─── Text Analysis ───────────────────────────────────────────
app.post('/scan/text', (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text is required' });

  const patterns = [
    { regex: /urgent|immediately|act now|account suspended/i, label: 'Urgency Tactics', score: 30 },
    { regex: /verify your|confirm your|update your account/i, label: 'Credential Phishing', score: 40 },
    { regex: /won|winner|congratulations|prize|lottery/i, label: 'Fake Reward Scam', score: 35 },
    { regex: /click here|click below|tap now/i, label: 'Clickbait Language', score: 20 },
    { regex: /password|ssn|credit card|bank account/i, label: 'Sensitive Data Request', score: 50 },
    { regex: /http[s]?:\/\/[^\s]+/i, label: 'Contains URL', score: 10 },
  ];

  const findings = [];
  let totalScore = 0;

  for (const p of patterns) {
    if (p.regex.test(text)) {
      findings.push({ pattern: p.label, score: p.score });
      totalScore += p.score;
    }
  }

  let riskLevel = 'LOW';
  if (totalScore >= 70) riskLevel = 'HIGH';
  else if (totalScore >= 40) riskLevel = 'MEDIUM';

  res.json({
    text: text.substring(0, 200),
    timestamp: new Date().toISOString(),
    findings,
    riskScore: Math.min(totalScore, 100),
    riskLevel,
  });
});

// ─── Health Check ────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    uptime: process.uptime(),
    apis: {
      virusTotal: VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here' ? 'configured' : 'not configured',
      googleSafeBrowsing: GSB_API_KEY && GSB_API_KEY !== 'your_google_safe_browsing_key_here' ? 'configured' : 'not configured',
    },
  });
});

// ═══════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

function runLocalHeuristics(url) {
  const warnings = [];
  let score = 0;

  // Typosquatting detection
  const brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'whatsapp', 'twitter'];
  const domain = url.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];

  for (const brand of brands) {
    if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.co`)) {
      warnings.push(`Possible typosquatting of ${brand}`);
      score += 40;
    }
  }

  // Suspicious TLDs
  const suspiciousTlds = ['.xyz', '.top', '.club', '.buzz', '.click', '.link', '.tk', '.ml', '.ga', '.cf'];
  if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
    warnings.push('Suspicious top-level domain');
    score += 25;
  }

  // URL shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'];
  if (shorteners.some(s => domain.includes(s))) {
    warnings.push('URL shortener detected');
    score += 15;
  }

  // Excessive subdomains
  if (domain.split('.').length > 4) {
    warnings.push('Excessive subdomains detected');
    score += 20;
  }

  // IP address URL
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
    warnings.push('Direct IP address in URL');
    score += 30;
  }

  return {
    status: warnings.length > 0 ? 'warning' : 'safe',
    detail: warnings.length > 0 ? warnings.join('; ') : 'No suspicious patterns detected',
    warnings,
    score: Math.min(score, 100),
  };
}

async function scanWithVirusTotal(url) {
  const response = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: {
      'x-apikey': VT_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `url=${encodeURIComponent(url)}`,
  });

  if (!response.ok) throw new Error(`VirusTotal API error: ${response.status}`);

  const data = await response.json();
  const analysisId = data.data?.id;

  if (!analysisId) return { status: 'unknown', detail: 'No analysis ID returned', score: 0 };

  // Wait briefly for analysis
  await new Promise(r => setTimeout(r, 3000));

  const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    headers: { 'x-apikey': VT_API_KEY },
  });

  if (!analysisResponse.ok) return { status: 'pending', detail: 'Analysis pending', score: 0 };

  const analysisData = await analysisResponse.json();
  const stats = analysisData.data?.attributes?.stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;

  return {
    status: malicious > 0 ? 'dangerous' : suspicious > 0 ? 'suspicious' : 'safe',
    detail: `${malicious} malicious, ${suspicious} suspicious detections`,
    malicious,
    suspicious,
    score: malicious > 0 ? 80 : suspicious > 0 ? 40 : 0,
  };
}

async function scanWithGoogleSafeBrowsing(url) {
  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'dlg-guardian', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    }
  );

  if (!response.ok) throw new Error(`Google Safe Browsing API error: ${response.status}`);

  const data = await response.json();
  const matches = data.matches || [];

  return {
    status: matches.length > 0 ? 'dangerous' : 'safe',
    detail: matches.length > 0 ? `Threats found: ${matches.map(m => m.threatType).join(', ')}` : 'No threats found',
    threats: matches.map(m => m.threatType),
    score: matches.length > 0 ? 90 : 0,
  };
}

async function checkFileHashVirusTotal(hash) {
  const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { 'x-apikey': VT_API_KEY },
  });

  if (response.status === 404) {
    return { status: 'unknown', detail: 'File hash not found in VirusTotal database', score: 0 };
  }

  if (!response.ok) throw new Error(`VirusTotal API error: ${response.status}`);

  const data = await response.json();
  const stats = data.data?.attributes?.last_analysis_stats || {};
  const malicious = stats.malicious || 0;

  return {
    status: malicious > 0 ? 'dangerous' : 'safe',
    detail: `${malicious} security vendors flagged this file`,
    malicious,
    score: malicious > 0 ? 90 : 0,
  };
}

// ─── Start Server ────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️  Digital Security Guardian API Server`);
  console.log(`   Running on http://0.0.0.0:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/health`);
  console.log(`\n   Endpoints:`);
  console.log(`   POST /scan/link   — Scan a URL`);
  console.log(`   POST /scan/file   — Scan an uploaded file`);
  console.log(`   POST /scan/text   — Analyze text for phishing`);
  console.log(`   GET  /health      — Server status\n`);
});
