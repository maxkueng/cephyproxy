import path from 'path';
import fs from 'fs';
import dns from 'dns';
import http from 'http';
import type { RequestListener } from 'http';
import https from 'https';
import express from 'express';
import { wrap } from 'async-middleware';
import cors from 'cors';
import httpProxy from 'http-proxy';
import { Counter, Gauge, register } from 'prom-client';
import type { Config } from './config';

function getPort(config: Config) {
  if (config.proxy.port) {
    return config.proxy.port;
  }
  if (config.proxy.ssl) {
    return 443;
  }
  return 80;
}

function createServer(config: Config, requestListener: RequestListener) {
  if (
    config.proxy.ssl
    && config.proxy.keyFile
    && config.proxy.certFile
  ) {
    const keyfilePath = path.resolve(config.proxy.keyFile);
    const certfilePath = path.resolve(config.proxy.certFile);

    return https.createServer({
      key: fs.readFileSync(keyfilePath, 'utf-8'),
      cert: fs.readFileSync(certfilePath, 'utf-8'),
    }, requestListener);
  }

  return http.createServer(requestListener);
}

export function startServer(config: Config) {
  const requestCounter = new Counter({
    name: 'cephyproxy_requests_total',
    help: 'Total HTTP requests received',
    labelNames: ['method', 'path', 'status'],
  });

  const dnsFailureCounter = new Counter({
    name: 'cephyproxy_dns_failures_total',
    help: 'Total failed DNS lookups',
  });

  const proxiedCounter = new Counter({
    name: 'cephyproxy_proxied_total',
    help: 'Total successfully proxied requests',
  });

  const startTimeGauge = new Gauge({
    name: 'cephyproxy_start_time_seconds',
    help: 'Start time of the proxy in seconds since epoch',
  });
  startTimeGauge.setToCurrentTime();
  if (config.dns?.address) {
    dns.setServers([`${config.dns.address}:${config.dns.port ?? 53}`]);
  }

  const resolveCNAME = async (hostname: string): Promise<string | null> => {
    try {
      const result = await dns.promises.resolveCname(hostname);
      return result[0] ?? null;
    } catch (err) {
      console.warn(`DNS resolution failed for ${hostname}:`, err);
      return null;
    }
  };

  const app = express();

  app.get('/metrics', async (_req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  app.use(cors({
    origin: '*',
  }));

  const proxy = httpProxy.createProxyServer({
    target: config.proxy.target,
    xfwd: false,
    secure: false,
  });

  proxy.on('proxyRes', (proxyRes, req, res) => {
    proxiedCounter.inc();
    const statusCode = proxyRes.statusCode ?? 502;
    requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.url ?? '', status: String(statusCode) });
    res.setHeader('access-control-allow-methods', '*');
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', '*');
    res.setHeader('access-control-allow-credentials', 'true');
  });

  app.get(['/livez', '/healthz'], (_req, res) => {
    res.sendStatus(200);
  });
  
  app.get('/readyz', async (req, res) => {
    const address = config.dns.address ?? dns.getServers()[0];
    const port = config.dns.port ?? 53;
  
    const resolver = new dns.Resolver();
    resolver.setServers([`${address}:${port}`]);
  
    resolver.resolve('nonexistent.example.com', 'A', (err, records) => {
      const isResponsive = !err || (err.code && err.code !== 'ETIMEOUT' && err.code !== 'EAI_AGAIN');
  
      if (isResponsive) {
        if ('verbose' in req.query) {
          res.status(200).type('text/plain').send(
            `[#] DNS check: ok` +
            `    using server ${address}:${port}` +
            `    DNS server responded with code: ${err?.code ?? 'NOERROR'}`
          );
        } else {
          res.sendStatus(200);
        }
      } else {
        if ('verbose' in req.query) {
          res.status(503).type('text/plain').send(
            `[#] DNS check: failed` +
            `    using server ${address}:${port}` +
            `    error: ${err?.code ?? 'unknown error'}`
          );
        } else {
          res.sendStatus(503);
        }
      }
    });
  });

  app.use(wrap(async (req, res) => {
    let statusCode = 200;
    const originalHost = req.headers.host;
    if (!originalHost) {
      requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.path, status: '400' });
      return res.status(400).send('Missing Host header');
    }

    if (config.debug) console.log({ originalHost });

    const cname = await resolveCNAME(originalHost);

    if (config.debug) console.log({ cname });

    if (!cname) {
      statusCode = 502;
      dnsFailureCounter.inc();
      requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.path, status: String(statusCode) });
      return res.status(502).send('Could not resolve target');
    }

    proxy.web(req, res, {
      target: config.proxy.target,
      changeOrigin: true,
      headers: { host: cname },
    }, (err) => {
      console.error('Proxy error:', err);
      statusCode = 502;
      requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.path, status: String(statusCode) });
      res.status(502).send('Proxy error');
    });
  }));

  const port = getPort(config);
  const server = createServer(config, app);

  server.listen(port, config.proxy.address, () => {
    const protocol = config.proxy.ssl ? 'https' : 'http';
    const host = config.proxy.address;
    const url = `${protocol}://${host}:${port}`;
    const dnsAddress = config.dns.address ? config.dns.address : dns.getServers().join(', ');

    console.info(`Listening at ${config.proxy.ssl ? 'https:' : 'http:'}//${config.proxy.address}:${port}`);
    console.info(`CephyProxy listening on ${url}`);
    console.info(`Proxy target: ${config.proxy.target}`);
    if (config.dns?.address) {
      console.info(`Using DNS server: ${dnsAddress}:${config.dns.port ?? 53}`);
    }
    if (config.debug) {
      console.info('Debug mode is enabled');
    }
  });

  return (callback?: () => void) => {
    server.close(() => {
      proxy.close(callback);
    });
  }
}
