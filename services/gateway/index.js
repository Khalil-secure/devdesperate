const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')
const axios = require('axios')

const app = express()
app.use(express.json())

// Gateway health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'gateway' })
})

// Proxy /ai/* to ai-service
app.use('/ai', createProxyMiddleware({
  target: 'http://ai-service:8000',
  changeOrigin: true,
  pathRewrite: { '^/ai': '' }
}))

// Manual proxy for phishing-detector (slow responses need full control)
app.use('/phishing', async (req, res) => {
  try {
    const url = `http://phishing-detector:8001${req.path}`
    const response = await axios({
      method: req.method,
      url: url,
      data: req.body,
      headers: { 'Content-Type': 'application/json' },
      timeout: 120000
    })
    res.status(response.status).json(response.data)
  } catch (err) {
    console.error('Phishing proxy error:', err.message)
    res.status(502).json({ error: 'Phishing service unavailable' })
  }
})

app.listen(3000, () => {
  console.log('Gateway running on port 3000')
})