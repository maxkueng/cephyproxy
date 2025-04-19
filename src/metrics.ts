import {
  Counter,
  Gauge,
  register,
} from 'prom-client';

export { register };

export const requestCounter = new Counter({
  name: 'cephyproxy_requests_total',
  help: 'Total HTTP requests received',
  labelNames: ['method', 'path', 'status'],
});

export const dnsFailureCounter = new Counter({
  name: 'cephyproxy_dns_failures_total',
  help: 'Total failed DNS lookups',
});

export const proxiedCounter = new Counter({
  name: 'cephyproxy_proxied_total',
  help: 'Total successfully proxied requests',
});

export const startTimeGauge = new Gauge({
  name: 'cephyproxy_start_time_seconds',
  help: 'Start time of the proxy in seconds since epoch',
});