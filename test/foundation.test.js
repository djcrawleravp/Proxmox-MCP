import test from 'node:test';
import assert from 'node:assert/strict';

import { ProxmoxServer, loadEnvironment, parseStrictBoolean } from '../index.js';
import {
  ProxmoxMcpError,
  RequestLimiter,
  TOOL_CLASSIFICATIONS,
  errorForHttpStatus,
  makeAuditEnvelope,
  redactSensitive,
  retryDelayMs,
} from '../foundation.js';

function setBaseEnv(overrides = {}) {
  process.env.PROXMOX_HOST = 'example.invalid';
  process.env.PROXMOX_TOKEN_VALUE = 'test-token';
  process.env.PROXMOX_VERIFY_TLS = 'true';
  delete process.env.PROXMOX_INSECURE_SKIP_TLS_VERIFY;
  delete process.env.PROXMOX_CA_BUNDLE;
  delete process.env.PROXMOX_ALLOW_ELEVATED;
  delete process.env.PROXMOX_ENABLE_GUEST_COMMAND_EXECUTION;
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  return new ProxmoxServer();
}

function response(ok, status, data) {
  return { ok, status, text: async () => data };
}

test('TLS verification is enabled by default and the insecure setting is explicit', () => {
  const secure = setBaseEnv({ PROXMOX_VERIFY_TLS: undefined });
  assert.equal(secure.verifyTls, true);

  const messages = [];
  const original = console.error;
  console.error = (message) => messages.push(message);
  try {
    const insecure = setBaseEnv({ PROXMOX_INSECURE_SKIP_TLS_VERIFY: 'true' });
    assert.equal(insecure.verifyTls, false);
  } finally {
    console.error = original;
  }
  assert.match(messages.join('\n'), /certificate verification is DISABLED/);
  assert.doesNotMatch(messages.join('\n'), /test-token/);
});

test('legacy insecure TLS configuration fails with a migration message', () => {
  assert.throws(() => setBaseEnv({ PROXMOX_VERIFY_TLS: 'false' }), /PROXMOX_INSECURE_SKIP_TLS_VERIFY/);
});

test('strict environment booleans and project-local/explicit environment precedence are deterministic', () => {
  assert.equal(parseStrictBoolean(undefined, { name: 'X' }), false);
  assert.equal(parseStrictBoolean('true', { name: 'X' }), true);
  assert.equal(parseStrictBoolean('false', { name: 'X' }), false);
  assert.throws(() => parseStrictBoolean('yes', { name: 'X' }), /exactly true or false/);
  const env = { PROXMOX_HOST: 'client.example', PROXMOX_ENV_FILE: '/explicit.env' };
  const loaded = loadEnvironment({ env, explicitPath: env.PROXMOX_ENV_FILE, localPath: '/project/.env', exists: (path) => path === '/explicit.env', read: () => 'PROXMOX_HOST=file.example\nPROXMOX_ALLOW_ELEVATED=true\n' });
  assert.deepEqual(loaded, { loaded: true, path: '/explicit.env' });
  assert.equal(env.PROXMOX_HOST, 'client.example');
  assert.equal(env.PROXMOX_ALLOW_ELEVATED, 'true');
  const local = {}; loadEnvironment({ env: local, localPath: '/project/.env', exists: (path) => path === '/project/.env', read: () => 'PROXMOX_ALLOW_ELEVATED=false\n' });
  assert.equal(local.PROXMOX_ALLOW_ELEVATED, 'false');
  assert.throws(() => loadEnvironment({ env: { PROXMOX_ENV_FILE: '/missing.env' }, explicitPath: '/missing.env', exists: () => false }), /does not exist/);
});

test('elevated mode is explicit and startup diagnostics never include a token', () => {
  const messages = []; const original = console.error; console.error = (message) => messages.push(message);
  try {
    assert.equal(setBaseEnv({ PROXMOX_ALLOW_ELEVATED: 'false' }).allowElevated, false);
    assert.equal(setBaseEnv({ PROXMOX_ALLOW_ELEVATED: 'true' }).allowElevated, true);
    assert.throws(() => setBaseEnv({ PROXMOX_ALLOW_ELEVATED: 'on' }), /exactly true or false/);
  } finally { console.error = original; }
  assert.match(messages.join('\n'), /elevated writes: ENABLED/);
  assert.doesNotMatch(messages.join('\n'), /test-token/);
});

test('requests time out through AbortController and expose a typed error', async () => {
  const server = setBaseEnv({ PROXMOX_REQUEST_TIMEOUT_MS: '1000', PROXMOX_READ_RETRY_ATTEMPTS: '0' });
  server.requestTimeoutMs = 10;
  server.fetch = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    });
  });
  await assert.rejects(server.proxmoxRequest('/version'), (error) => error.code === 'PROXMOX_REQUEST_TIMEOUT' && error.category === 'timeout');
});

test('GET retries transient network failures but POST is never retried', async () => {
  const server = setBaseEnv({ PROXMOX_READ_RETRY_ATTEMPTS: '2' });
  server.sleep = async () => {};
  let getCalls = 0;
  server.fetch = async () => {
    getCalls += 1;
    if (getCalls === 1) {
      const error = new Error('ECONNRESET');
      error.code = 'ECONNRESET';
      throw error;
    }
    return response(true, 200, JSON.stringify({ data: { version: 'test' } }));
  };
  assert.deepEqual(await server.proxmoxRequest('/version'), { version: 'test' });
  assert.equal(getCalls, 2);

  let postCalls = 0;
  server.fetch = async () => {
    postCalls += 1;
    const error = new Error('ECONNRESET');
    error.code = 'ECONNRESET';
    throw error;
  };
  await assert.rejects(server.proxmoxRequest('/nodes/pve1/qemu', 'POST', { vmid: 100 }), (error) => error.code === 'PROXMOX_NETWORK_ERROR');
  assert.equal(postCalls, 1);
});

test('authentication and certificate failures are never retried', async () => {
  const server = setBaseEnv({ PROXMOX_READ_RETRY_ATTEMPTS: '2' });
  server.sleep = async () => {};
  let calls = 0;
  server.fetch = async () => { calls += 1; return response(false, 401, 'authentication failure'); };
  await assert.rejects(server.proxmoxRequest('/version'), (error) => error.code === 'PROXMOX_AUTHENTICATION_FAILED');
  assert.equal(calls, 1);

  const tls = new Error('self signed certificate');
  const typed = new ProxmoxMcpError({ code: 'PROXMOX_TLS_ERROR', category: 'tls', message: tls.message });
  assert.equal(typed.retryable, false);
});

test('retry delay is bounded and jittered', () => {
  assert.equal(retryDelayMs(0, null, () => 0), 125);
  assert.equal(retryDelayMs(20, null, () => 1), 5000);
  assert.equal(retryDelayMs(0, 9000), 5000);
});

test('request limiter observes its configured FIFO concurrency boundary', async () => {
  const limiter = new RequestLimiter(2);
  let active = 0;
  let maximum = 0;
  const order = [];
  const work = (id) => limiter.run(async () => {
    active += 1;
    maximum = Math.max(maximum, active);
    order.push(`start-${id}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    order.push(`end-${id}`);
    return id;
  });
  assert.deepEqual(await Promise.all([work(1), work(2), work(3)]), [1, 2, 3]);
  assert.equal(maximum, 2);
  assert.ok(order.indexOf('start-3') > order.indexOf('end-1') || order.indexOf('start-3') > order.indexOf('end-2'));
});

test('errors redact common credential formats and retain safe API status', () => {
  const raw = 'PVEAPIToken=root@pam!mcp=abc token=abc password=hunter2 Authorization=Bearer abc';
  const redacted = redactSensitive(raw);
  assert.doesNotMatch(redacted, /hunter2|abc/);
  const error = errorForHttpStatus(403, raw, '/access/acl');
  assert.equal(error.code, 'PROXMOX_PERMISSION_DENIED');
  assert.equal(error.statusCode, 403);
  assert.doesNotMatch(error.message, /hunter2|abc/);
});

test('audit envelope is stable, machine-readable, and separates warnings from failures', () => {
  const success = makeAuditEnvelope({ ok: true, tool: 'proxmox_get_node_status', classification: 'READ', data: { uptime: 1 }, source: { type: 'proxmox-api', endpoint: '/nodes/pve1/status', node: 'pve1' }, warnings: ['partial metric'] });
  assert.equal(success.ok, true);
  assert.equal(success.evidence.retrievalMethod, 'REST');
  assert.deepEqual(success.warnings, ['partial metric']);
  const failure = makeAuditEnvelope({ ok: false, tool: 'proxmox_get_node_status', classification: 'READ', error: errorForHttpStatus(403, 'denied', '/nodes/pve1/status') });
  assert.equal(failure.error.code, 'PROXMOX_PERMISSION_DENIED');
  assert.equal(failure.data, undefined);
});

test('classification inventory marks inspected tools READ and mutating tools WRITE', () => {
  for (const name of ['proxmox_get_node_status', 'proxmox_list_snapshots_vm', 'proxmox_list_snapshots_lxc', 'proxmox_list_backups', 'proxmox_get_guest_ips']) {
    assert.equal(TOOL_CLASSIFICATIONS[name], 'READ', name);
  }
  assert.equal(TOOL_CLASSIFICATIONS.proxmox_start_vm, 'WRITE');
  assert.equal(TOOL_CLASSIFICATIONS.proxmox_execute_vm_command, 'WRITE');
});

test('reclassified READ tools operate without write enablement and writes remain guarded', async () => {
  const server = setBaseEnv();
  const calls = [];
  server.proxmoxRequest = async (endpoint) => {
    calls.push(endpoint);
    if (endpoint.endsWith('/status')) return { uptime: 1, loadavg: [], cpu: 0, memory: { used: 0, total: 1 }, rootfs: { used: 0, total: 1 } };
    if (endpoint.endsWith('/snapshot')) return [{ name: 'current' }];
    if (endpoint.includes('content?content=backup')) return [];
    return { result: [] };
  };
  assert.equal((await server.getNodeStatus('pve1')).isError, undefined);
  assert.equal((await server.listSnapshots('pve1', '100', 'qemu')).isError, undefined);
  assert.equal((await server.listBackups('pve1', 'local')).isError, undefined);
  assert.equal((await server.getGuestIPs('pve1', '100')).isError, undefined);
  assert.match((await server.startVM('pve1', '100', 'qemu')).content[0].text, /Requires Elevated Permissions/);
  assert.equal(calls.some((endpoint) => endpoint.includes('/status/start')), false);
});

test('generic guest command execution requires its dedicated explicit gate', async () => {
  const server = setBaseEnv({ PROXMOX_ALLOW_ELEVATED: 'true' });
  const result = await server.executeVMCommand('pve1', '100', 'id', 'qemu', false);
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /disabled/i);
});
