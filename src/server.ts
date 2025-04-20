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
import pino from 'pino';
import pinoPretty from 'pino-pretty';

import type { Config } from './config';
import {
  register,
  startTimeGauge,
  requestCounter,
  proxiedCounter,
  dnsFailureCounter,
} from './metrics';

const logger = pino(pinoPretty({
  colorize: false,
}));

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
  startTimeGauge.setToCurrentTime();
  
  if (config.debug) {
    logger.level = 'debug';
  }

  if (config.dns?.address) {
    dns.setServers([`${config.dns.address}:${config.dns.port ?? 53}`]);
  }

  const resolveCNAME = async (hostname: string): Promise<string | null> => {
    try {
      const result = await dns.promises.resolveCname(hostname);
      return result[0] ?? null;
    } catch (err) {
      logger.warn(`DNS resolution failed for ${hostname}:`, err);
      return null;
    }
  };

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
  
  proxy.on('proxyReq', (proxyReq, req, res) => {
    const resolvedHost = (req as any).__resolvedHost;
    if (resolvedHost) {
      proxyReq.setHeader('host', resolvedHost);
    }
    
    proxyReq.removeHeader('x-forwarded-host');
    proxyReq.removeHeader('x-forwarded-proto');
    proxyReq.removeHeader('x-forwarded-port');
    proxyReq.removeHeader('x-forwarded-for');

    logger.debug('Outgoing request headers to target:');
    logger.debug(proxyReq.getHeaders());
  });

  const app = express();

  app.use(cors({
    origin: '*',
  }));
  
  const internalRoute = (
    path: string | string[],
    handler: express.RequestHandler,
  ) => {
    app.get(path, (req, res, next) => {
      const host = req.headers.host?.split(':')[0];
      const isProxyDomain = host && config.proxy.allowedDomains.some(suffix => host.endsWith(suffix));
      if (isProxyDomain) {
        return next();
      }
      handler(req, res, next);
    });
  };

  internalRoute('/metrics', async (_req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  });

  internalRoute(['/livez', '/healthz'], (_req, res) => {
    res.sendStatus(200);
  });
  
  internalRoute('/readyz', async (req, res) => {
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
    logger.debug(`Original host: ${originalHost}`);

    if (!originalHost) {
      requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.path, status: '400' });
      return res.status(400).send('Missing Host header');
    }
    
    const hostname = originalHost.split(':')[0];
    const isAllowedDomain = config.proxy.allowedDomains.some(suffix =>
      hostname.endsWith(suffix)
    );

    if (!isAllowedDomain) {
      return res.status(403).send('Forbidden: host not in allowedDomains');
    }

    const cname = await resolveCNAME(originalHost);
    logger.debug(`Resolved CNAME: ${cname}`);

    if (!cname) {
      statusCode = 502;
      dnsFailureCounter.inc();
      requestCounter.inc({ method: req.method ?? 'UNKNOWN', path: req.path, status: String(statusCode) });
      return res.status(502).send('Could not resolve target');
    }
    
    (req as any).__resolvedHost = cname;
    
    proxy.web(req, res, {
      target: config.proxy.target,
      headers: { host: cname },
      secure: false,
    }, (err) => {
      logger.error('Proxy error:', err);
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

    logger.info(`CephyProxy listening on ${url}`);
    logger.info(`Proxy target: ${config.proxy.target}`);
    if (config.dns?.address) {
      logger.info(`Using DNS server: ${dnsAddress}:${config.dns.port ?? 53}`);
    }
    if (config.debug) {
      logger.info('Debug mode is enabled');
    }
  });

  return (callback?: () => void) => {
    server.close(() => {
      proxy.close(callback);
    });
  }
}
