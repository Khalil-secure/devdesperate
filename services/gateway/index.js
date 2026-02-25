const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')

const app = express()
app.use(express.json())

// Gateway own health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'gateway' })
})

// Proxy /ai/* requests to the ai-service
app.use('/ai', createProxyMiddleware({
  target: 'http://ai-service:8000',
  changeOrigin: true,
  pathRewrite: { '^/ai': '' }
}))

app.listen(3000, () => {
  console.log('Gateway running on port 3000')
})