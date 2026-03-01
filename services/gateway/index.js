const express = require('express')
const cors = require('cors')
const axios = require('axios')
const jwt = require('jsonwebtoken')
const { Pool } = require('pg')
const { createProxyMiddleware } = require('http-proxy-middleware')

const app = express()
app.use(cors({ origin: true, credentials: true }))
app.use(express.json())

// PostgreSQL
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      google_id VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(255),
      avatar VARCHAR(500),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      scanned_at TIMESTAMP DEFAULT NOW()
    );
  `)
  console.log('✅ Database initialized')
}

initDB().catch(console.error)

// ── IP RATE LIMITING ──
const ipRequests = new Map()
const ipFreeScans = new Map()

function ipRateLimit(req, res, next) {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip
  const now = Date.now()
  const windowMs = 60 * 60 * 1000 // 1 hour
  const max = 100

  if (!ipRequests.has(ip)) ipRequests.set(ip, [])
  const requests = ipRequests.get(ip).filter(t => now - t < windowMs)
  requests.push(now)
  ipRequests.set(ip, requests)

  if (requests.length > max) {
    return res.status(429).json({ error: 'Too many requests from this IP. Try again later.' })
  }
  next()
}

// ── FREE TIER — 5 scans before login ──
function checkFreeTier(req, res, next) {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip
  const now = Date.now()
  const windowMs = 24 * 60 * 60 * 1000

  if (!ipFreeScans.has(ip)) ipFreeScans.set(ip, [])
  const scans = ipFreeScans.get(ip).filter(t => now - t < windowMs)

  if (scans.length >= 5) {
    return res.status(401).json({
      error: 'free_limit_reached',
      message: 'You have used all 5 free scans. Sign in with Google for 10 scans/day free.',
      scans_used: scans.length,
      limit: 5
    })
  }

  scans.push(now)
  ipFreeScans.set(ip, scans)
  req.freeScansUsed = scans.length
  req.freeScansRemaining = 5 - scans.length
  next()
}

  scans.push(now)
  ipFreeScans.set(ip, scans)
  req.freeScansUsed = scans.length
  req.freeScansRemaining = 5 - scans.length
  next()
}

// ── JWT MIDDLEWARE ──
function verifyToken(req, res, next) {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) return next() // no token = anonymous
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET)
  } catch {
    // invalid token = treat as anonymous
  }
  next()
}

// ── ROUTE GUARD — logged in OR free tier ──
function requireAccessOrFree(req, res, next) {
  if (req.user) return next() // logged in — skip free tier check
  return checkFreeTier(req, res, next) // anonymous — check free tier
}

// ── PER USER RATE LIMIT — 10 scans/day ──
async function checkUserRateLimit(req, res, next) {
  if (!req.user) return next() // anonymous handled by checkFreeTier
  const result = await pool.query(`
    SELECT COUNT(*) FROM scans
    WHERE user_id = $1
    AND scanned_at > NOW() - INTERVAL '24 hours'
  `, [req.user.id])

  const count = parseInt(result.rows[0].count)
  if (count >= 10) {
    return res.status(429).json({
      error: 'daily_limit_reached',
      message: 'You have used all 10 free scans today. Upgrade to Pro for unlimited scans.',
      scans_used: count,
      limit: 10
    })
  }
  req.scans_used = count
  next()
}

async function recordScan(userId) {
  await pool.query('INSERT INTO scans (user_id) VALUES ($1)', [userId])
}

// ── ROUTES ──

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'gateway' })
})

// Google OAuth
app.get('/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline'
  })
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`)
})

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_CALLBACK_URL,
      grant_type: 'authorization_code'
    })

    const userRes = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
    })

    const { id, email, name, picture } = userRes.data
    const result = await pool.query(`
      INSERT INTO users (google_id, email, name, avatar)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (google_id) DO UPDATE
      SET name = $3, avatar = $4
      RETURNING *
    `, [id, email, name, picture])

    const user = result.rows[0]
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, avatar: user.avatar },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.redirect(`https://mail-guard-beta.vercel.app?token=${token}&name=${encodeURIComponent(name)}`)
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message)
    res.redirect('https://mail-guard-beta.vercel.app?error=auth_failed')
  }
})

app.get('/auth/me', verifyToken, async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' })
  const scans = await pool.query(`
    SELECT COUNT(*) FROM scans
    WHERE user_id = $1
    AND scanned_at > NOW() - INTERVAL '24 hours'
  `, [req.user.id])

  res.json({
    ...req.user,
    scans_used: parseInt(scans.rows[0].count),
    scans_remaining: Math.max(0, 10 - parseInt(scans.rows[0].count))
  })
})

// AI proxy
app.use('/ai', createProxyMiddleware({
  target: 'http://ai-service:8000',
  changeOrigin: true,
  pathRewrite: { '^/ai': '' }
}))

// Phishing proxy — free tier OR logged in
app.use('/phishing', ipRateLimit, verifyToken, requireAccessOrFree, checkUserRateLimit, async (req, res) => {
  try {
    const targetPath = req.originalUrl.replace('/phishing', '')
    const url = `http://phishing-detector:8001${targetPath || '/'}`
    const response = await axios({
      method: req.method,
      url,
      data: req.body,
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    })

    if (req.user) await recordScan(req.user.id)

    // Add scan info to response
    const data = response.data
    if (!req.user) {
      data._free_scans_remaining = req.freeScansRemaining
      data._free_scans_used = req.freeScansUsed
    }

    res.status(response.status).json(data)
  } catch (err) {
    console.error('Phishing proxy error:', err.message)
    res.status(502).json({ error: 'Phishing service unavailable' })
  }
})

app.listen(3000, () => console.log('Gateway running on port 3000'))