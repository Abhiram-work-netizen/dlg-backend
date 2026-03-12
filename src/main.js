require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const dns = require('dns');
const { promisify } = require('util');

const dnsResolve = promisify(dns.resolve);

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ──────────────────────────────────────
app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// ─── File Upload Config ──────────────────────────────────────
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 50 * 1024 * 1024 },
});

// ─── API Keys ────────────────────────────────────────────────
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const GSB_API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY || '';

// ═══════════════════════════════════════════════════════════════
// REAL LINK SCANNER — Multi-layer threat analysis
// ═══════════════════════════════════════════════════════════════
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

    // Layer 1: Smart Heuristic Analysis (always runs)
    const heuristicCheck = runSmartHeuristics(url);
    results.checks.push({ source: 'Smart Heuristic Analysis', ...heuristicCheck });
    results.riskScore += heuristicCheck.score;

    // Layer 2: URLhaus — Real malware URL database (FREE, no key)
    try {
      const urlhausResult = await checkURLhaus(url);
      results.checks.push({ source: 'URLhaus (abuse.ch)', ...urlhausResult });
      results.riskScore += urlhausResult.score;
    } catch (e) {
      results.checks.push({ source: 'URLhaus (abuse.ch)', status: 'unavailable', detail: e.message, score: 0 });
    }

    // Layer 3: DNS Resolution Check (FREE, no key)
    try {
      const dnsResult = await checkDNS(url);
      results.checks.push({ source: 'DNS Resolution', ...dnsResult });
      results.riskScore += dnsResult.score;
    } catch (e) {
      results.checks.push({ source: 'DNS Resolution', status: 'unavailable', detail: e.message, score: 0 });
    }

    // Layer 4: VirusTotal (if API key configured)
    if (VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here') {
      try {
        const vtResult = await scanWithVirusTotal(url);
        results.checks.push({ source: 'VirusTotal', ...vtResult });
        results.riskScore += vtResult.score;
      } catch (e) {
        results.checks.push({ source: 'VirusTotal', status: 'unavailable', detail: e.message, score: 0 });
      }
    }

    // Layer 5: Google Safe Browsing (if API key configured)
    if (GSB_API_KEY && GSB_API_KEY !== 'your_google_safe_browsing_key_here') {
      try {
        const gsbResult = await scanWithGoogleSafeBrowsing(url);
        results.checks.push({ source: 'Google Safe Browsing', ...gsbResult });
        results.riskScore += gsbResult.score;
      } catch (e) {
        results.checks.push({ source: 'Google Safe Browsing', status: 'unavailable', detail: e.message, score: 0 });
      }
    }

    // Cap score at 100 and determine risk level
    results.riskScore = Math.min(results.riskScore, 100);
    if (results.riskScore >= 60) results.riskLevel = 'HIGH';
    else if (results.riskScore >= 30) results.riskLevel = 'MEDIUM';
    else results.riskLevel = 'LOW';

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Scan failed', detail: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// FILE SCANNER
// ═══════════════════════════════════════════════════════════════
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

    // File type analysis
    const ext = path.extname(req.file.originalname).toLowerCase();
    const dangerousExts = ['.exe', '.bat', '.cmd', '.scr', '.msi', '.vbs', '.js', '.jar', '.apk', '.dll', '.ps1', '.reg'];
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

    // URLhaus file hash check (FREE, no key)
    try {
      const hashResult = await checkURLhausHash(fileHash);
      results.checks.push({ source: 'URLhaus Hash Check', ...hashResult });
      results.riskScore += hashResult.score;
    } catch (e) {
      results.checks.push({ source: 'URLhaus Hash Check', status: 'unavailable', detail: e.message, score: 0 });
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

    results.riskScore = Math.min(results.riskScore, 100);
    if (results.riskScore >= 60) results.riskLevel = 'HIGH';
    else if (results.riskScore >= 30) results.riskLevel = 'MEDIUM';
    else results.riskLevel = 'LOW';

    fs.unlinkSync(req.file.path);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'File scan failed', detail: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// TEXT PHISHING ANALYZER
// ═══════════════════════════════════════════════════════════════
app.post('/scan/text', (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text is required' });

  const patterns = [
    { regex: /urgent|immediately|act now|account suspended|action required/i, label: 'Urgency Tactics', score: 30 },
    { regex: /verify your|confirm your|update your account|validate your/i, label: 'Credential Phishing', score: 40 },
    { regex: /won|winner|congratulations|prize|lottery|selected/i, label: 'Fake Reward Scam', score: 35 },
    { regex: /click here|click below|tap now|open link/i, label: 'Clickbait Language', score: 20 },
    { regex: /password|ssn|credit card|bank account|social security/i, label: 'Sensitive Data Request', score: 50 },
    { regex: /http[s]?:\/\/[^\s]+/i, label: 'Contains URL', score: 10 },
    { regex: /dear customer|dear user|dear account holder/i, label: 'Generic Greeting (Phishing)', score: 25 },
    { regex: /suspended|blocked|locked|unauthorized/i, label: 'Fear-Based Language', score: 30 },
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
  if (totalScore >= 60) riskLevel = 'HIGH';
  else if (totalScore >= 30) riskLevel = 'MEDIUM';

  res.json({
    text: text.substring(0, 200),
    timestamp: new Date().toISOString(),
    findings,
    riskScore: Math.min(totalScore, 100),
    riskLevel,
  });
});

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '2.0.0',
    uptime: process.uptime(),
    engines: {
      smartHeuristics: 'active',
      urlhaus: 'active (free)',
      dnsCheck: 'active (free)',
      virusTotal: VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here' ? 'active' : 'not configured',
      googleSafeBrowsing: GSB_API_KEY && GSB_API_KEY !== 'your_google_safe_browsing_key_here' ? 'active' : 'not configured',
    },
  });
});

// ═══════════════════════════════════════════════════════════════
// SMART HEURISTIC ENGINE — Fuzzy typosquatting + deep analysis
// ═══════════════════════════════════════════════════════════════

function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function runSmartHeuristics(url) {
  const warnings = [];
  let score = 0;

  let normalizedUrl = url.trim().toLowerCase();
  if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(normalizedUrl);
  } catch {
    return { status: 'warning', detail: 'Malformed URL — cannot be parsed', warnings: ['URL is malformed'], score: 50 };
  }

  const domain = parsedUrl.hostname;
  const domainParts = domain.split('.');
  // Extract the main domain name (e.g., "macrosoft" from "www.macrosoft.com")
  const mainDomain = domainParts.length >= 2
    ? domainParts[domainParts.length - 2]
    : domainParts[0];

  // ── 1. FUZZY TYPOSQUATTING (Levenshtein distance) ──────────
  const brands = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft',
    'paypal', 'netflix', 'instagram', 'whatsapp', 'twitter',
    'linkedin', 'youtube', 'snapchat', 'tiktok', 'telegram',
    'banking', 'chase', 'wellsfargo', 'citibank', 'barclays',
  ];

  for (const brand of brands) {
    const distance = levenshtein(mainDomain, brand);
    const maxLen = Math.max(mainDomain.length, brand.length);
    const similarity = 1 - (distance / maxLen);

    // If domain is very similar (but not identical) to a known brand → suspicious
    if (similarity >= 0.65 && mainDomain !== brand) {
      warnings.push(`"${mainDomain}" is ${Math.round(similarity * 100)}% similar to "${brand}" — possible typosquatting`);
      score += Math.round(similarity * 60);
    }
  }

  // ── 2. Leetspeak detection (number substitutions) ──────────
  const leetMap = { '0': 'o', '1': 'il', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a' };
  let deleetedDomain = mainDomain;
  for (const [num, letters] of Object.entries(leetMap)) {
    deleetedDomain = deleetedDomain.replace(new RegExp(num.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), letters[0]);
  }

  if (deleetedDomain !== mainDomain) {
    for (const brand of brands) {
      const distance = levenshtein(deleetedDomain, brand);
      const maxLen = Math.max(deleetedDomain.length, brand.length);
      const similarity = 1 - (distance / maxLen);

      if (similarity >= 0.7) {
        warnings.push(`"${mainDomain}" uses number substitution — decoded to "${deleetedDomain}", ${Math.round(similarity * 100)}% match with "${brand}"`);
        score += Math.round(similarity * 70);
        break;
      }
    }
  }

  // ── 3. Suspicious TLDs ──────────────────────────────────────
  const suspiciousTlds = ['.xyz', '.top', '.club', '.buzz', '.click', '.link', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.icu', '.cam', '.bid', '.win', '.loan', '.work', '.site', '.fun', '.live'];
  const tld = '.' + domainParts[domainParts.length - 1];
  if (suspiciousTlds.includes(tld)) {
    warnings.push(`Suspicious TLD "${tld}" — commonly used in phishing`);
    score += 20;
  }

  // ── 4. URL shorteners ──────────────────────────────────────
  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'short.io', 'rebrand.ly', 'rb.gy'];
  if (shorteners.some(s => domain.includes(s))) {
    warnings.push('URL shortener — the real destination is hidden');
    score += 15;
  }

  // ── 5. Excessive subdomains ─────────────────────────────────
  if (domainParts.length > 4) {
    warnings.push(`${domainParts.length} subdomain levels — likely an obfuscation attempt`);
    score += 20;
  }

  // ── 6. IP address URL ──────────────────────────────────────
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    warnings.push('Uses raw IP address instead of a domain — legitimate sites use domains');
    score += 30;
  }

  // ── 7. @ symbol (credential injection) ─────────────────────
  if (url.includes('@')) {
    warnings.push('Contains "@" — possible credential injection attack');
    score += 35;
  }

  // ── 8. Suspicious path/domain keywords ─────────────────────
  const fullUrl = normalizedUrl;
  const suspiciousKeywords = ['login', 'signin', 'verify', 'confirm', 'account', 'secure', 'update', 'banking', 'password', 'credential', 'claim', 'reward', 'prize', 'winner', 'wallet', 'recover', 'suspended'];
  for (const keyword of suspiciousKeywords) {
    if (fullUrl.includes(keyword)) {
      warnings.push(`Contains suspicious keyword "${keyword}"`);
      score += 15;
      break;
    }
  }

  // ── 9. HTTPS check ─────────────────────────────────────────
  if (parsedUrl.protocol === 'http:') {
    warnings.push('Uses HTTP instead of HTTPS — connection is not encrypted');
    score += 10;
  }

  // ── 10. Unusually long domain ──────────────────────────────
  if (domain.length > 40) {
    warnings.push(`Very long domain (${domain.length} characters) — often used in phishing`);
    score += 15;
  }

  // ── 11. Contains hyphens in domain ─────────────────────────
  if (mainDomain.includes('-') && brands.some(b => mainDomain.includes(b))) {
    warnings.push('Brand name with hyphens — common phishing pattern (e.g. "amazon-support")');
    score += 25;
  }

  return {
    status: warnings.length > 0 ? 'warning' : 'safe',
    detail: warnings.length > 0 ? warnings.join('; ') : 'No suspicious patterns detected',
    warnings,
    score: Math.min(score, 100),
  };
}

// ═══════════════════════════════════════════════════════════════
// URLhaus — Real malware URL database (FREE, no API key needed)
// https://urlhaus.abuse.ch/api/
// ═══════════════════════════════════════════════════════════════

async function checkURLhaus(url) {
  const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}`,
  });

  if (!response.ok) throw new Error(`URLhaus error: ${response.status}`);

  const data = await response.json();

  if (data.query_status === 'no_results') {
    return { status: 'safe', detail: 'URL not found in malware database', score: 0 };
  }

  if (data.query_status === 'ok' || data.threat) {
    return {
      status: 'dangerous',
      detail: `THREAT DETECTED — ${data.threat || 'malware_download'} (reported ${data.url_count || 0} times)`,
      threat: data.threat,
      tags: data.tags || [],
      score: 90,
    };
  }

  return { status: 'unknown', detail: 'Could not determine URL status', score: 0 };
}

async function checkURLhausHash(hash) {
  const response = await fetch('https://urlhaus-api.abuse.ch/v1/payload/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `sha256_hash=${hash}`,
  });

  if (!response.ok) throw new Error(`URLhaus error: ${response.status}`);

  const data = await response.json();

  if (data.query_status === 'no_results' || data.query_status === 'hash_not_found') {
    return { status: 'safe', detail: 'File hash not found in malware database', score: 0 };
  }

  if (data.query_status === 'ok') {
    return {
      status: 'dangerous',
      detail: `MALWARE DETECTED — ${data.signature || 'unknown'} (${data.url_count || 0} distribution URLs)`,
      signature: data.signature,
      score: 95,
    };
  }

  return { status: 'unknown', detail: 'Could not determine file status', score: 0 };
}

// ═══════════════════════════════════════════════════════════════
// DNS Resolution Check — Verifies if domain actually exists
// ═══════════════════════════════════════════════════════════════

async function checkDNS(url) {
  let normalizedUrl = url.trim().toLowerCase();
  if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  let hostname;
  try {
    hostname = new URL(normalizedUrl).hostname;
  } catch {
    return { status: 'warning', detail: 'Cannot parse URL for DNS check', score: 10 };
  }

  try {
    const addresses = await dnsResolve(hostname);
    if (addresses && addresses.length > 0) {
      return { status: 'safe', detail: `Domain resolves to ${addresses[0]}`, ip: addresses[0], score: 0 };
    }
    return { status: 'warning', detail: 'Domain does not resolve — may not exist', score: 20 };
  } catch (e) {
    if (e.code === 'ENOTFOUND') {
      return { status: 'warning', detail: 'Domain does not exist (NXDOMAIN)', score: 25 };
    }
    return { status: 'warning', detail: `DNS lookup failed: ${e.code || e.message}`, score: 10 };
  }
}

// ═══════════════════════════════════════════════════════════════
// VirusTotal API (requires free API key)
// ═══════════════════════════════════════════════════════════════

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
    detail: `${malicious} malicious, ${suspicious} suspicious detections out of ${(stats.harmless || 0) + malicious + suspicious} engines`,
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
        client: { clientId: 'dlg-guardian', clientVersion: '2.0.0' },
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
    detail: matches.length > 0 ? `Threats: ${matches.map(m => m.threatType).join(', ')}` : 'No threats found',
    threats: matches.map(m => m.threatType),
    score: matches.length > 0 ? 90 : 0,
  };
}

async function checkFileHashVirusTotal(hash) {
  const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { 'x-apikey': VT_API_KEY },
  });

  if (response.status === 404) {
    return { status: 'unknown', detail: 'File hash not in VirusTotal database', score: 0 };
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
  console.log(`\n🛡️  Digital Security Guardian API v2.0`);
  console.log(`   Running on http://0.0.0.0:${PORT}`);
  console.log(`\n   Active Engines:`);
  console.log(`   ✅ Smart Heuristics (fuzzy typosquatting + Levenshtein)`);
  console.log(`   ✅ URLhaus (abuse.ch — real malware database)`);
  console.log(`   ✅ DNS Resolution Check`);
  console.log(`   ${VT_API_KEY && VT_API_KEY !== 'your_virustotal_key_here' ? '✅' : '⬜'} VirusTotal`);
  console.log(`   ${GSB_API_KEY && GSB_API_KEY !== 'your_google_safe_browsing_key_here' ? '✅' : '⬜'} Google Safe Browsing`);
  console.log(`\n   Endpoints:`);
  console.log(`   POST /scan/link   — Multi-layer URL scan`);
  console.log(`   POST /scan/file   — File hash + type analysis`);
  console.log(`   POST /scan/text   — Phishing text analysis`);
  console.log(`   GET  /health      — Server status\n`);
});
