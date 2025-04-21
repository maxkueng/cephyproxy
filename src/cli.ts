#!/usr/bin/env node

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { loadConfig } from './config';
import { startServer } from './server';

const argv = yargs(hideBin(process.argv))
  .option('config', {
    alias: 'c',
    type: 'string',
    description: 'Path to config file',
  })
  .option('debug', {
    type: 'boolean',
    default: false,
    description: 'Enable debug logging',
  })
  .parseSync();

const configPath = argv.config;
const config = loadConfig({
  configPath,
  defaults: {
    debug: argv.debug,
  },
});

const stopServer = startServer(config);

const shutdown = (signal: string, value: number) => {
  stopServer(() => {
    console.log(`Server stopped by ${signal} with value ${value}`);
    process.exit(128 + value);
  });
};

const signals = {
  'SIGHUP': 1,
  'SIGINT': 2,
  'SIGTERM': 15,
};

Object.entries(signals).forEach(([signal, value]) => {
  process.on(signal, () => {
    console.log(`Process received a ${signal} signal`);
    shutdown(signal, value);
  });
});