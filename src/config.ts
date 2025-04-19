import fs from 'fs';
import path from 'path';
import * as toml from 'toml';
import { z } from 'zod';

export const configSchema = z.object({
  debug: z.boolean().default(false),

  proxy: z.object({
    port: z.number().optional(),
    address: z.string().default('127.0.0.1'),
    ssl: z.boolean().default(false),
    keyFile: z.string().optional(),
    certFile: z.string().optional(),
    target: z.string().url(),
  }).refine(
    (proxy) => !proxy.ssl || (proxy.keyFile && proxy.certFile),
    {
      message: 'keyFile and certFile are required when ssl is true',
      path: ['ssl'],
    }
  ),

  dns: z.object({
    address: z.string().ip().optional(),
    port: z.number().int().default(53),
  }),
});


export type Config = z.infer<typeof configSchema>;

type LoadConfigOptions = {
  defaults: Partial<Config>;
  configPath?: string;
};

export function loadConfig({
  configPath,
  defaults,
}: LoadConfigOptions) {
  const resolvedPath = configPath
    ? path.resolve(configPath)
    : path.join(process.cwd(), 'cephyproxy.toml');

  const rawToml = fs.readFileSync(resolvedPath, 'utf-8');
  const parsed = toml.parse(rawToml);

  const config = configSchema.parse(parsed);

  return {
    ...defaults,
    ...config,
  };
}
