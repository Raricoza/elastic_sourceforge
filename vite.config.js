import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { request as httpReq } from 'http'
import { request as httpsReq } from 'https'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    {
      name: 'es-proxy',
      configureServer(server) {
        server.middlewares.use('/es-proxy', (req, res) => {
          const targetBase = req.headers['x-es-url']
          if (!targetBase) {
            res.statusCode = 400
            res.end('Missing X-ES-URL header')
            return
          }

          let target
          try { target = new URL(targetBase.replace(/\/$/, '') + (req.url || '/')) }
          catch { res.statusCode = 400; res.end('Invalid X-ES-URL'); return }

          const headers = { ...req.headers }
          delete headers['x-es-url']
          delete headers['host']

          const reqFn = target.protocol === 'https:' ? httpsReq : httpReq
          const proxyReq = reqFn(
            {
              hostname: target.hostname,
              port: target.port || (target.protocol === 'https:' ? 443 : 80),
              path: target.pathname + target.search,
              method: req.method,
              headers,
              rejectUnauthorized: false, // allow self-signed certs
            },
            proxyRes => {
              // allow browser to read the response
              const responseHeaders = {
                ...proxyRes.headers,
                'access-control-allow-origin': '*',
              }
              res.writeHead(proxyRes.statusCode, responseHeaders)
              proxyRes.pipe(res)
            }
          )

          proxyReq.on('error', e => {
            res.statusCode = 502
            res.end(JSON.stringify({ error: e.message }))
          })

          req.pipe(proxyReq)
        })
      },
    },
    {
      name: 'kibana-proxy',
      configureServer(server) {
        server.middlewares.use('/kibana-proxy', (req, res) => {
          const targetBase = req.headers['x-kibana-url']
          if (!targetBase) {
            res.statusCode = 400
            res.end('Missing X-Kibana-URL header')
            return
          }

          let target
          try { target = new URL(targetBase.replace(/\/$/, '') + (req.url || '/')) }
          catch { res.statusCode = 400; res.end('Invalid X-Kibana-URL'); return }

          const headers = { ...req.headers }
          delete headers['x-kibana-url']
          delete headers['host']

          const reqFn = target.protocol === 'https:' ? httpsReq : httpReq
          const proxyReq = reqFn(
            {
              hostname: target.hostname,
              port: target.port || (target.protocol === 'https:' ? 443 : 80),
              path: target.pathname + target.search,
              method: req.method,
              headers,
              rejectUnauthorized: false,
            },
            proxyRes => {
              const responseHeaders = {
                ...proxyRes.headers,
                'access-control-allow-origin': '*',
              }
              res.writeHead(proxyRes.statusCode, responseHeaders)
              proxyRes.pipe(res)
            }
          )

          proxyReq.on('error', e => {
            res.statusCode = 502
            res.end(JSON.stringify({ error: e.message }))
          })

          req.pipe(proxyReq)
        })
      },
    },
  ],
})
