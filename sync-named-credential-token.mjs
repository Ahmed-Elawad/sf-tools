#!/usr/bin/env node

import { constants as cryptoConstants, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const SCRIPT_DIR = dirname(SCRIPT_PATH);

const EXIT = { ok: 0, config: 1, token: 2, tokenValidation: 3, sfAuth: 4, ncUpdate: 5, fatal: 70, interrupted: 130 };

class StepError extends Error {
  constructor(exitCode, message) {
    super(message);
    this.exitCode = exitCode;
  }
}


const { values: flags } = parseArgs({
  options: {
    env: { type: 'string' },
    every: { type: 'string' },
    once: { type: 'boolean', default: false },
    supervise: { type: 'boolean', default: false },
    'dry-run': { type: 'boolean', default: false },
    verbose: { type: 'boolean', short: 'v', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
  strict: true,
});

if (flags.help) {
  console.log(`Usage: node sync-named-credential-token.mjs [options]

Options:
  --env <path>       .env file to load (default: ENV_FILE or ./.env next to this script)
  --every <minutes>  Keep running and refresh on this interval (overrides RUN_INTERVAL_MINUTES)
  --once             Run a single cycle and exit even if RUN_INTERVAL_MINUTES is set
  --supervise        Run as a parent process that restarts the worker if it crashes (signal / fatal error)
  --dry-run          One cycle, everything except the PUT to Salesforce; prints the redacted PUT body
  -v, --verbose      Extra diagnostics (claims, JWKS URI, PUT bodies with secrets redacted)
  -h, --help         Show this help

Exit codes: 0 ok, 1 config, 2 token request, 3 token validation, 4 Salesforce auth,
            5 named credential update(s) failed, 70 fatal error, 130 interrupted by signal`);
  process.exit(EXIT.ok);
}


function loadEnvFile(file) {
  if (!existsSync(file)) return false;
  if (typeof process.loadEnvFile === 'function') {
    process.loadEnvFile(file);
    return true;
  }
  for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2];
    if (/^(['"]).*\1$/.test(value)) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    if (process.env[m[1]] === undefined) process.env[m[1]] = value;
  }
  return true;
}

const envFile = resolve(flags.env ?? process.env.ENV_FILE ?? resolve(SCRIPT_DIR, '.env'));
const envLoaded = loadEnvFile(envFile);

const env = (name, fallback) => {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
};
const list = (value) =>
  (value ?? '')
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);


const ROLE = flags.supervise ? 'supervisor' : 'worker';
const LOG_MAX_BYTES = Number(env('LOG_MAX_MB', '10')) * 1024 * 1024;
let logFilePath = null;
let logFileBroken = false;

(function initLogFile() {
  const setting = env('LOG_FILE', 'logs/sync-named-credential-token.log');
  if (setting.toLowerCase() === 'none') return;
  logFilePath = resolve(SCRIPT_DIR, setting);
  try {
    mkdirSync(dirname(logFilePath), { recursive: true });
  } catch (e) {
    console.error(`! cannot create log directory for ${logFilePath}: ${e.message}; continuing with console only`);
    logFilePath = null;
  }
})();

function toFile(level, msg) {
  if (!logFilePath || logFileBroken) return;
  const text = String(msg).trim();
  if (!text) return;
  try {
    if (LOG_MAX_BYTES > 0 && existsSync(logFilePath) && statSync(logFilePath).size >= LOG_MAX_BYTES) {
      renameSync(logFilePath, `${logFilePath}.1`);
    }
    appendFileSync(logFilePath, `${new Date().toISOString()} ${ROLE}[${process.pid}] ${level.padEnd(5)} ${text.replace(/\n/g, '\n    ')}\n`);
  } catch (e) {
    logFileBroken = true;
    console.error(`! log file ${logFilePath} is not writable (${e.message}); continuing with console only`);
  }
}

const log = (msg) => {
  console.log(msg);
  toFile('INFO', msg);
};
const info = (msg) => {
  console.log(`      ${msg}`);
  toFile('INFO', msg);
};
const warn = (msg) => {
  console.warn(`      ! ${msg}`);
  toFile('WARN', msg);
};
const error = (msg) => {
  console.error(`✖ ${msg}`);
  toFile('ERROR', msg);
};
const debug = (msg) => {
  if (!flags.verbose) return;
  console.log(`      · ${msg}`);
  toFile('DEBUG', msg);
};
const fail = (code, msg) => {
  error(msg);
  process.exit(code);
};

const preview = (secret) =>
  typeof secret === 'string' && secret.length > 12
    ? `${secret.slice(0, 8)}…(${secret.length} chars)`
    : '(short value)';
const truncate = (s, n = 400) => (s.length > n ? `${s.slice(0, n)}…` : s);
const safeJson = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};
const rssMb = () => Math.round(process.memoryUsage().rss / 1048576);


const shutdown = new AbortController();
const STOP_GRACE_MS = Number(env('STOP_GRACE_SECONDS', '20')) * 1000;
let stopRequested = null;
let wake = null; 
let onStop = null;

function requestStop(signal) {
  const now = Date.now();
  if (stopRequested) {
    if (now - stopRequested.at < 1000) return; // same signal delivered twice (terminal + supervisor forward)
    error(`${signal} received again - aborting immediately`);
    shutdown.abort();
    process.exit(EXIT.interrupted);
  }
  stopRequested = { signal, at: now };
  if (flags.supervise) log(`${signal} received - forwarding to the worker and stopping`);
  else log(`${signal} received - stopping${wake ? '' : ` (in-flight work gets ${STOP_GRACE_MS / 1000}s to finish)`}`);
  wake?.();
  onStop?.(signal);
  setTimeout(() => {
    if (!shutdown.signal.aborted) {
      warn('grace period over - aborting in-flight requests');
      shutdown.abort();
    }
  }, STOP_GRACE_MS).unref();
}
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => requestStop(sig));

process.on('uncaughtException', (e, origin) => {
  error(`FATAL (${origin}): ${e?.stack ?? e}`);
  shutdown.abort();
  process.exit(EXIT.fatal);
});
process.on('unhandledRejection', (reason) => {
  error(`FATAL (unhandledRejection): ${reason?.stack ?? reason}`);
  shutdown.abort();
  process.exit(EXIT.fatal);
});
process.on('warning', (w) => toFile('WARN', `process warning ${w.name}: ${w.message}`));
process.on('exit', (code) => toFile(code === 0 ? 'INFO' : 'ERROR', `exit code ${code}${stopRequested ? ` after ${stopRequested.signal}` : ''} (rss ${rssMb()} MB)`));
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (e) => {
    if (e.code !== 'EPIPE') throw e; // a closed pipe on the reader side is not our fault
  });
}

const sleep = (ms) =>
  new Promise((resolve) => {
    const timer = setTimeout(() => {
      wake = null;
      resolve();
    }, ms);
    wake = () => {
      clearTimeout(timer);
      wake = null;
      resolve();
    };
  });



const required = (name) => {
  const v = env(name);
  if (v === undefined) fail(EXIT.config, `Missing required variable ${name} (looked in ${envFile}${envLoaded ? '' : ' - file not found'} and the environment)`);
  return v;
};

const cfg = {
  tokenUrl: required('TOKEN_URL'),
  clientId: required('CLIENT_ID'),
  clientSecret: required('CLIENT_SECRET'),
  scope: env('SCOPE'),
  grantType: env('GRANT_TYPE', 'client_credentials'),
  tokenValidation: env('TOKEN_VALIDATION', 'strict').toLowerCase(), // strict | off
  jwksUri: env('JWKS_URI'),
  expectedIssuer: env('EXPECTED_ISSUER'),
  allowedAlgs: list(env('TOKEN_ALGS', 'RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512,EdDSA')),
  leewaySeconds: Number(env('TOKEN_LEEWAY_SECONDS', '60')),
  sfApiVersion: env('SF_API_VERSION', '66.0').replace(/^v/i, ''),
  sfTargetOrg: env('SF_TARGET_ORG'),
  sfAccessToken: env('SF_ACCESS_TOKEN'),
  sfInstanceUrl: env('SF_INSTANCE_URL'),
  sfLoginUrl: env('SF_LOGIN_URL', 'https://login.salesforce.com'),
  sfClientId: env('SF_CLIENT_ID'),
  sfClientSecret: env('SF_CLIENT_SECRET'),
  namedCredentials: list(required('NAMED_CREDENTIALS')),
  headerName: env('HEADER_NAME', 'authorizationCode'),
  headerValuePrefix: env('HEADER_VALUE_PREFIX', ''),
  stripKeys: list(env('SF_NC_STRIP_KEYS', 'id,url')),
  timeoutMs: Number(env('HTTP_TIMEOUT_MS', '30000')),
  // Step 5: scheduling (0 = run once)
  intervalMinutes: Number(flags.every ?? env('RUN_INTERVAL_MINUTES', '0')),
  retryMinutes: Number(env('RETRY_INTERVAL_MINUTES', '5')),
};

if (cfg.namedCredentials.length === 0) fail(EXIT.config, 'NAMED_CREDENTIALS is empty');
if (!['strict', 'off'].includes(cfg.tokenValidation)) fail(EXIT.config, 'TOKEN_VALIDATION must be "strict" or "off"');
if (!Number.isFinite(cfg.intervalMinutes) || cfg.intervalMinutes < 0) fail(EXIT.config, 'RUN_INTERVAL_MINUTES / --every must be a number of minutes >= 0');
if (!Number.isFinite(cfg.retryMinutes) || cfg.retryMinutes <= 0) fail(EXIT.config, 'RETRY_INTERVAL_MINUTES must be a number of minutes > 0');
if (!Number.isFinite(cfg.timeoutMs) || cfg.timeoutMs <= 0) fail(EXIT.config, 'HTTP_TIMEOUT_MS must be a number > 0');

/** Per-request signal: the per-call timeout, or the process-wide shutdown, whichever comes first. */
const requestSignal = () => AbortSignal.any([shutdown.signal, AbortSignal.timeout(cfg.timeoutMs)]);
const describeFetchError = (e) =>
  shutdown.signal.aborted ? 'aborted by shutdown' : e.name === 'TimeoutError' ? `timed out after ${cfg.timeoutMs} ms` : (e.cause?.message ?? e.message);


async function fetchAccessToken() {
  const form = new URLSearchParams();
  form.set('client_id', cfg.clientId);
  form.set('client_secret', cfg.clientSecret);
  if (cfg.scope) form.set('scope', cfg.scope);
  form.set('grant_type', cfg.grantType);

  let res;
  try {
    res = await fetch(cfg.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: form.toString(),
      signal: requestSignal(),
    });
  } catch (e) {
    throw new Error(`Could not reach token endpoint ${cfg.tokenUrl}: ${describeFetchError(e)}`);
  }
  const text = await res.text();
  const json = safeJson(text);
  if (!json) throw new Error(`Token endpoint returned non-JSON (HTTP ${res.status}): ${truncate(text)}`);
  if (!res.ok) {
    throw new Error(`Token request failed (HTTP ${res.status}): ${json.error ?? ''} ${json.error_description ?? truncate(text)}`.trim());
  }
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new Error(`Token response has no access_token. Keys received: ${Object.keys(json).join(', ') || '(none)'}`);
  }
  return json;
}


const ALG = {
  RS256: { kty: 'RSA', hash: 'sha256' },
  RS384: { kty: 'RSA', hash: 'sha384' },
  RS512: { kty: 'RSA', hash: 'sha512' },
  PS256: { kty: 'RSA', hash: 'sha256', pss: true },
  PS384: { kty: 'RSA', hash: 'sha384', pss: true },
  PS512: { kty: 'RSA', hash: 'sha512', pss: true },
  ES256: { kty: 'EC', hash: 'sha256', crv: 'P-256' },
  ES384: { kty: 'EC', hash: 'sha384', crv: 'P-384' },
  ES512: { kty: 'EC', hash: 'sha512', crv: 'P-521' },
  EdDSA: { kty: 'OKP', hash: null },
};

function decodeJws(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('access_token is not a compact JWS (expected header.payload.signature). If the token is opaque, set TOKEN_VALIDATION=off.');
  }
  const header = safeJson(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = safeJson(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (!header || !payload) throw new Error('access_token header/payload is not valid base64url JSON');
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
}

async function fetchJson(url, what) {
  let res;
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' }, signal: requestSignal() });
  } catch (e) {
    throw new Error(`Could not fetch ${what} at ${url}: ${describeFetchError(e)}`);
  }
  const text = await res.text();
  const json = safeJson(text);
  if (!res.ok || !json) throw new Error(`Fetching ${what} at ${url} failed (HTTP ${res.status}): ${truncate(text)}`);
  return json;
}

async function resolveJwksUri(claims) {
  if (cfg.jwksUri) return cfg.jwksUri;
  const iss = claims.iss;
  if (typeof iss !== 'string' || !/^https?:\/\//.test(iss)) {
    throw new Error(`Cannot discover JWKS: token "iss" claim is ${JSON.stringify(iss)}. Set JWKS_URI in .env.`);
  }
  const discoveryUrl = `${iss.replace(/\/+$/, '')}/.well-known/openid-configuration`;
  debug(`OIDC discovery: ${discoveryUrl}`);
  const meta = await fetchJson(discoveryUrl, 'OpenID configuration');
  if (typeof meta.jwks_uri !== 'string') throw new Error(`OpenID configuration at ${discoveryUrl} has no jwks_uri. Set JWKS_URI in .env.`);
  return meta.jwks_uri;
}

function verifyJwsSignature(jws, jwk) {
  const spec = ALG[jws.header.alg];
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const opts = { key };
  if (spec.pss) {
    opts.padding = cryptoConstants.RSA_PKCS1_PSS_PADDING;
    opts.saltLength = cryptoConstants.RSA_PSS_SALTLEN_DIGEST;
  }
  if (spec.kty === 'EC') opts.dsaEncoding = 'ieee-p1363';
  return cryptoVerify(spec.hash, Buffer.from(jws.signingInput, 'ascii'), opts, jws.signature);
}

async function validateAccessToken(token) {
  const jws = decodeJws(token);
  const { alg, kid } = jws.header;
  if (!ALG[alg]) throw new Error(`Unsupported JWT alg "${alg}" (symmetric/none algorithms are refused)`);
  if (!cfg.allowedAlgs.includes(alg)) throw new Error(`JWT alg "${alg}" is not in TOKEN_ALGS (${cfg.allowedAlgs.join(',')})`);

  const jwksUri = await resolveJwksUri(jws.payload);
  debug(`JWKS: ${jwksUri}`);
  const jwks = await fetchJson(jwksUri, 'JWKS');
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const spec = ALG[alg];
  const candidates = keys.filter(
    (k) =>
      k.kty === spec.kty &&
      (!kid || k.kid === kid) &&
      (!k.alg || k.alg === alg) &&
      (!k.use || k.use === 'sig') &&
      (!spec.crv || k.crv === spec.crv),
  );
  if (candidates.length === 0) {
    throw new Error(`No key in ${jwksUri} matches kid=${JSON.stringify(kid)} alg=${alg} (${keys.length} key(s) published)`);
  }

  let verified = false;
  for (const jwk of candidates) {
    try {
      if (verifyJwsSignature(jws, jwk)) {
        verified = true;
        break;
      }
    } catch (e) {
      debug(`key ${jwk.kid ?? '(no kid)'} unusable: ${e.message}`);
    }
  }
  if (!verified) throw new Error(`JWT signature verification FAILED (alg=${alg}, kid=${kid ?? 'none'}, ${candidates.length} candidate key(s))`);

  const now = Math.floor(Date.now() / 1000);
  const { exp, nbf, iss } = jws.payload;
  if (typeof exp === 'number' && exp <= now - cfg.leewaySeconds) {
    throw new Error(`Token already expired at ${new Date(exp * 1000).toISOString()}`);
  }
  if (typeof nbf === 'number' && nbf > now + cfg.leewaySeconds) {
    throw new Error(`Token not valid before ${new Date(nbf * 1000).toISOString()}`);
  }
  if (cfg.expectedIssuer && iss !== cfg.expectedIssuer) {
    throw new Error(`Token issuer ${JSON.stringify(iss)} does not match EXPECTED_ISSUER ${cfg.expectedIssuer}`);
  }
  return { alg, kid, exp, claims: jws.payload, jwksUri };
}


async function authorizeSalesforce() {
  if (cfg.sfAccessToken && cfg.sfInstanceUrl) {
    return { instanceUrl: cfg.sfInstanceUrl, accessToken: cfg.sfAccessToken, source: 'SF_ACCESS_TOKEN / SF_INSTANCE_URL' };
  }
  if (cfg.sfClientId && cfg.sfClientSecret) {
    const url = `${cfg.sfLoginUrl.replace(/\/+$/, '')}/services/oauth2/token`;
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: cfg.sfClientId, client_secret: cfg.sfClientSecret });
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: form.toString(),
        signal: requestSignal(),
      });
    } catch (e) {
      throw new Error(`Could not reach ${url}: ${describeFetchError(e)}`);
    }
    const json = safeJson(await res.text()) ?? {};
    if (!res.ok || !json.access_token) {
      throw new Error(`Salesforce client-credentials login at ${url} failed (HTTP ${res.status}): ${json.error ?? ''} ${json.error_description ?? ''}`.trim());
    }
    return { instanceUrl: json.instance_url, accessToken: json.access_token, source: `client credentials (${cfg.sfLoginUrl})` };
  }

  // Default: reuse an org already authorized in the Salesforce CLI (sf org display also refreshes the session).
  const args = ['org', 'display', '--json'];
  if (cfg.sfTargetOrg) args.push('--target-org', cfg.sfTargetOrg);
  let stdout;
  try {
    ({ stdout } = await execFileAsync('sf', args, {
      maxBuffer: 10 * 1024 * 1024,
      shell: process.platform === 'win32',
      signal: shutdown.signal,
      timeout: cfg.timeoutMs * 2,
    }));
  } catch (e) {
    const out = safeJson(e.stdout ?? '');
    const detail = shutdown.signal.aborted
      ? 'aborted by shutdown'
      : (out?.message ?? out?.name ?? (e.code === 'ENOENT' ? 'sf CLI not found on PATH' : truncate(e.stderr || e.message)));
    throw new Error(`sf org display${cfg.sfTargetOrg ? ` -o ${cfg.sfTargetOrg}` : ''} failed: ${detail}`);
  }
  const out = safeJson(stdout);
  const r = out?.result;
  if (out?.status !== 0 || !r?.accessToken || !r?.instanceUrl) {
    throw new Error(`Unexpected sf org display output: ${truncate(stdout)}`);
  }
  if (r.connectedStatus && r.connectedStatus !== 'Connected') {
    warn(`sf CLI reports connectedStatus=${r.connectedStatus}; re-authenticate with: sf org login web -o ${cfg.sfTargetOrg ?? r.alias ?? r.username}`);
  }
  return {
    instanceUrl: r.instanceUrl,
    accessToken: r.accessToken,
    username: r.username,
    source: `sf CLI (${cfg.sfTargetOrg ?? r.alias ?? 'default org'})`,
  };
}

async function sfRequest(org, method, path, body) {
  const url = new URL(path, org.instanceUrl);
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${org.accessToken}`,
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: requestSignal(),
    });
  } catch (e) {
    throw new Error(`${method} ${url} failed: ${describeFetchError(e)}`);
  }
  const text = await res.text();
  const json = text ? safeJson(text) : null;
  if (!res.ok) {
    let detail = truncate(text);
    if (Array.isArray(json)) detail = json.map((e) => `${e.errorCode ?? 'ERROR'}: ${e.message ?? JSON.stringify(e)}`).join('; ');
    else if (json?.message) detail = `${json.errorCode ?? 'ERROR'}: ${json.message}`;
    if (res.status === 401) detail += ' (Salesforce session expired or invalid - re-authenticate the org)';
    const err = new Error(`${method} ${url.pathname} -> HTTP ${res.status}: ${detail}`);
    err.status = res.status;
    throw err;
  }
  return json;
}


const ncPath = (developerName) =>
  `/services/data/v${cfg.sfApiVersion}/named-credentials/named-credential-setup/${encodeURIComponent(developerName)}`;

/** Recursively drop output-only keys (id, url, ...) so the GET representation becomes a valid PUT input. */
function stripOutputOnlyKeys(value) {
  if (Array.isArray(value)) return value.map(stripOutputOnlyKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (cfg.stripKeys.includes(k) || v === null) continue;
      out[k] = stripOutputOnlyKeys(v);
    }
    return out;
  }
  return value;
}

function buildPutBody(nc, headerValue) {
  const body = stripOutputOnlyKeys(nc);

  body.externalCredentials = (nc.externalCredentials ?? []).map((e) => ({ developerName: e.developerName }));
  if (nc.networkConnection?.developerName) body.networkConnection = { developerName: nc.networkConnection.developerName };

  const headers = (nc.customHeaders ?? []).map((h) => ({
    headerName: h.headerName,
    headerValue: h.headerValue,
    sequenceNumber: h.sequenceNumber,
  }));
  const idx = headers.findIndex((h) => String(h.headerName).toLowerCase() === cfg.headerName.toLowerCase());
  let action;
  if (idx >= 0) {
    headers[idx].headerValue = headerValue;
    action = `updated existing header "${headers[idx].headerName}" (sequence ${headers[idx].sequenceNumber})`;
  } else {
    const next = headers.reduce((m, h) => Math.max(m, Number(h.sequenceNumber) || 0), 0) + 1;
    headers.push({ headerName: cfg.headerName, headerValue, sequenceNumber: next });
    action = `added header "${cfg.headerName}" (sequence ${next})`;
  }
  body.customHeaders = headers;
  return { body, action };
}

const redactBody = (body, headerValue) =>
  JSON.stringify(body, (k, v) => (k === 'headerValue' && v === headerValue ? `<access token ${preview(v)}>` : v), 2);

async function updateNamedCredential(org, developerName, headerValue) {
  const current = await sfRequest(org, 'GET', ncPath(developerName));
  const { body, action } = buildPutBody(current, headerValue);
  debug(`PUT body for ${developerName}:\n${redactBody(body, headerValue)}`);

  if (flags['dry-run']) {
    info(`${developerName}: DRY RUN - would have ${action}`);
    if (!flags.verbose) info(redactBody(body, headerValue).replace(/\n/g, '\n      '));
    return;
  }

  await sfRequest(org, 'PUT', ncPath(developerName), body);

  const after = await sfRequest(org, 'GET', ncPath(developerName));
  const stored = (after.customHeaders ?? []).find((h) => String(h.headerName).toLowerCase() === cfg.headerName.toLowerCase());
  if (!stored) throw new Error(`${developerName}: PUT succeeded but header "${cfg.headerName}" is missing on re-read`);
  if (stored.headerValue !== headerValue) throw new Error(`${developerName}: PUT succeeded but header "${cfg.headerName}" does not hold the new token on re-read`);
  info(`${developerName}: ${action} ✔`);
}


const minutesUntil = (ts) => Math.max(0, Math.round((ts - Date.now()) / 60000));

async function runCycle() {
  log(`[1/4] Requesting access token from ${cfg.tokenUrl} (grant_type=${cfg.grantType}${cfg.scope ? `, scope=${cfg.scope}` : ''})`);
  let tokenResponse;
  try {
    tokenResponse = await fetchAccessToken();
  } catch (e) {
    throw new StepError(EXIT.token, e.message);
  }
  const accessToken = tokenResponse.access_token;
  const expiresIn = Number(tokenResponse.expires_in);
  let expiresAt = Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : null;
  info(`access_token received: ${preview(accessToken)}${tokenResponse.expires_in ? `, expires_in=${tokenResponse.expires_in}s` : ''}${tokenResponse.token_type ? `, token_type=${tokenResponse.token_type}` : ''}`);

  log('[2/4] Validating access token signature');
  if (cfg.tokenValidation === 'off') {
    warn('TOKEN_VALIDATION=off - signature check skipped');
  } else {
    try {
      const v = await validateAccessToken(accessToken);
      if (typeof v.exp === 'number') expiresAt = v.exp * 1000;
      const expIn = expiresAt ? `, expires in ${minutesUntil(expiresAt)} min` : '';
      info(`${v.alg} signature valid (kid=${v.kid ?? 'none'}, keys from ${v.jwksUri})${expIn}`);
      debug(`claims: ${JSON.stringify(v.claims)}`);
    } catch (e) {
      throw new StepError(EXIT.tokenValidation, `Access token rejected: ${e.message}`);
    }
  }
  if (expiresAt && cfg.intervalMinutes > 0 && expiresAt - Date.now() < cfg.intervalMinutes * 60000) {
    warn(`token expires in ${minutesUntil(expiresAt)} min but the refresh interval is ${cfg.intervalMinutes} min - lower RUN_INTERVAL_MINUTES to avoid a gap`);
  }

  log('[3/4] Authorizing to Salesforce');
  let org;
  try {
    org = await authorizeSalesforce();
  } catch (e) {
    throw new StepError(EXIT.sfAuth, e.message);
  }
  info(`${org.instanceUrl}${org.username ? ` as ${org.username}` : ''} via ${org.source}, API v${cfg.sfApiVersion}`);

  const headerValue = `${cfg.headerValuePrefix}${accessToken}`;
  log(`[4/4] Setting custom header "${cfg.headerName}" on ${cfg.namedCredentials.length} named credential(s): ${cfg.namedCredentials.join(', ')}`);
  const failures = [];
  for (const name of cfg.namedCredentials) {
    if (shutdown.signal.aborted) {
      failures.push(name);
      warn(`${name}: skipped, shutdown in progress`);
      continue;
    }
    try {
      await updateNamedCredential(org, name, headerValue);
    } catch (e) {
      failures.push(name);
      warn(`${name}: ${e.message}`);
    }
  }

  const okCount = cfg.namedCredentials.length - failures.length;
  if (failures.length > 0) {
    throw new StepError(EXIT.ncUpdate, `${okCount} succeeded, ${failures.length} failed: ${failures.join(', ')}`);
  }
  log(`✔ ${okCount} named credential(s) ${flags['dry-run'] ? 'checked (dry run)' : 'updated'}`);
}


const describeError = (e) => (e instanceof StepError ? e.message : (e.stack ?? e.message));

async function workerMain() {
  toFile('INFO', `start node ${process.version} pid ${process.pid} args [${process.argv.slice(2).join(' ')}] cwd ${process.cwd()}`);
  log(`Loaded ${envLoaded ? envFile : 'environment only (no .env file found)'}${flags['dry-run'] ? '  [DRY RUN]' : ''}${logFilePath ? `, logging to ${logFilePath}` : ''}`);
  const loop = cfg.intervalMinutes > 0 && !flags.once && !flags['dry-run'];

  if (!loop) {
    try {
      await runCycle();
    } catch (e) {
      if (stopRequested) fail(EXIT.interrupted, `interrupted by ${stopRequested.signal}: ${describeError(e)}`);
      fail(e instanceof StepError ? e.exitCode : EXIT.config, describeError(e));
    }
    return;
  }

  log(`Refreshing every ${cfg.intervalMinutes} min (retrying ${cfg.retryMinutes} min after a failed cycle). Ctrl-C to stop.`);
  let cycle = 0;
  while (!stopRequested) {
    cycle += 1;
    const started = Date.now();
    log(`\n━━ cycle ${cycle} at ${new Date(started).toISOString()} ━━`);
    let ok = false;
    try {
      await runCycle();
      ok = true;
      info(`cycle ${cycle} done in ${((Date.now() - started) / 1000).toFixed(1)}s (rss ${rssMb()} MB)`);
    } catch (e) {
      error(`cycle ${cycle} failed after ${((Date.now() - started) / 1000).toFixed(1)}s: ${describeError(e)}`);
    }
    if (stopRequested) break;
    const waitMs = ok ? Math.max(0, cfg.intervalMinutes * 60_000 - (Date.now() - started)) : cfg.retryMinutes * 60_000;
    log(`next cycle at ${new Date(Date.now() + waitMs).toISOString()}${ok ? '' : ' (retry)'}`);
    await sleep(waitMs);
  }
  log('Stopped.');
}


async function supervisorMain() {
  const workerArgs = process.argv.slice(2).filter((a) => a !== '--supervise');
  toFile('INFO', `start node ${process.version} pid ${process.pid} args [${process.argv.slice(2).join(' ')}] cwd ${process.cwd()}`);
  log(`Supervisor pid ${process.pid}: restarts the worker after a crash (signal or fatal error). Ctrl-C to stop.`);

  let worker = null;
  let attempt = 0;
  onStop = (signal) => worker?.kill(signal);

  for (;;) {
    const startedAt = Date.now();
    worker = spawn(process.execPath, [SCRIPT_PATH, ...workerArgs], { stdio: 'inherit', env: process.env });
    log(`supervisor: worker pid ${worker.pid} started`);
    const [code, signal] = await new Promise((res) => {
      worker.once('exit', (c, s) => res([c, s]));
      worker.once('error', (e) => res([EXIT.fatal, `spawn error: ${e.message}`]));
    });
    worker = null;
    const ranSec = Math.round((Date.now() - startedAt) / 1000);
    const how = signal ? `terminated by ${signal}` : `exited with code ${code}`;
    const crashed = signal !== null || code === EXIT.fatal;

    if (stopRequested || !crashed) {
      const exitCode = code ?? EXIT.interrupted;
      log(`supervisor: worker ${how} after ${ranSec}s${stopRequested ? ' (stop requested)' : ''} - exiting with ${exitCode}`);
      process.exit(exitCode);
    }

    attempt = ranSec > 600 ? 1 : attempt + 1; // a worker that ran > 10 min resets the backoff
    const delayMs = Math.min(5_000 * 2 ** (attempt - 1), 300_000);
    error(`supervisor: worker crashed (${how}) after ${ranSec}s - restarting in ${delayMs / 1000}s (attempt ${attempt})`);
    await sleep(delayMs);
    if (stopRequested) process.exit(EXIT.interrupted);
  }
}

(flags.supervise ? supervisorMain() : workerMain()).catch((e) => fail(EXIT.fatal, e.stack ?? e.message));
