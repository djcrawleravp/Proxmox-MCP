import test from 'node:test';
import assert from 'node:assert/strict';
import { ProxmoxServer } from '../index.js';
import { auditToolDefinitions } from '../audit-readers.js';
import { TOOL_CLASSIFICATIONS } from '../foundation.js';

function server(routes = {}) {
  process.env.PROXMOX_HOST = 'example.invalid'; process.env.PROXMOX_TOKEN_VALUE = 'test-token'; process.env.PROXMOX_VERIFY_TLS = 'true';
  delete process.env.PROXMOX_ALLOW_ELEVATED;
  const value = new ProxmoxServer(); value.sleep = async () => {};
  value.proxmoxRequest = async (endpoint) => {
    const route = Object.entries(routes).filter(([prefix]) => endpoint.startsWith(prefix)).sort(([a], [b]) => b.length - a.length)[0];
    if (!route) throw new Error(`unexpected endpoint ${endpoint}`);
    const response = route[1]; if (response instanceof Error) throw response;
    return typeof response === 'function' ? response(endpoint) : response;
  };
  return value;
}

test('all Phase 2B reader definitions are centrally READ classified', () => {
  assert.equal(auditToolDefinitions.length, 33);
  for (const tool of auditToolDefinitions) {
    assert.equal(TOOL_CLASSIFICATIONS[tool.name], 'READ', tool.name);
    assert.equal(tool.annotations.readOnlyHint, true, tool.name);
  }
});

test('node DNS reader and writer use the Proxmox DNS endpoint with dry-run and postcondition verification', async () => {
  const calls = []; let state = { dns1: '10.10.10.254', dns2: '1.1.1.1', dns3: null, search: 'old.example' };
  const s = server({});
  s.proxmoxRequest = async (endpoint, method = 'GET', body = null) => {
    calls.push({ endpoint, method, body });
    if (endpoint !== '/nodes/pve1/dns') throw new Error(`unexpected endpoint ${endpoint}`);
    if (method === 'GET') return { ...state };
    if (method === 'PUT') {
      for (const field of body.delete || []) state[field] = null;
      for (const field of ['dns1', 'dns2', 'dns3', 'search']) if (body[field] !== undefined) state[field] = body[field];
      return {};
    }
    throw new Error(`unexpected method ${method}`);
  };
  const read = await s.auditReaders.handle('proxmox_get_node_dns', { node: 'pve1' });
  assert.equal(read.structuredContent.dns.dns1, '10.10.10.254');
  assert.equal(read.structuredContent.file, '/etc/resolv.conf');
  const plan = await s.auditReaders.handle('proxmox_update_node_dns', { node: 'pve1', dns1: '10.10.10.1', search: 'triii', clear_dns2: true });
  assert.equal(plan.structuredContent.dry_run, true);
  assert.deepEqual(plan.structuredContent.request.body, { dns1: '10.10.10.1', search: 'triii', delete: ['dns2'] });
  assert.equal(calls.some((call) => call.method === 'PUT'), false);
  s.allowElevated = true;
  const changed = await s.auditReaders.handle('proxmox_update_node_dns', { node: 'pve1', dns1: '10.10.10.1', search: 'triii', clear_dns2: true, dry_run: false, confirm: true });
  assert.equal(changed.structuredContent.postcondition_verified, true);
  assert.deepEqual(changed.structuredContent.after, { dns1: '10.10.10.1', dns2: null, dns3: null, search: 'triii' });
  assert.equal(changed.structuredContent.reloadRequired, false);
  assert.equal(calls.filter((call) => call.method === 'PUT').length, 1);
  const invalid = await s.auditReaders.handle('proxmox_update_node_dns', { node: 'pve1', dns1: 'not-an-ip' });
  assert.equal(invalid.isError, true);
  const empty = await s.auditReaders.handle('proxmox_update_node_dns', { node: 'pve1', clear_dns1: true });
  assert.equal(empty.isError, true);
});

test('SDN apply requires explicit acknowledgement of the Proxmox network reload', async () => {
  const s = server({
    '/cluster/sdn/vnets?pending=1': [],
    '/cluster/sdn/vnets?running=1': [],
  });
  s.allowElevated = true;
  const result = await s.auditReaders.handle('proxmox_apply_sdn_configuration', {
    dry_run: false,
    confirm_apply_all_pending: true,
  });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /confirm_network_reload/i);
});

test('task reader validates pagination and preserves API path/filter evidence', async () => {
  const s = server({ '/cluster/tasks': [{ status: 'stopped', exitstatus: 'OK', starttime: 2 }] });
  const result = await s.auditReaders.handle('proxmox_list_tasks', { limit: 20, start: 4, status: 'all', vmid: '100' });
  assert.equal(result.structuredContent.page.limit, 20);
  assert.match(result.structuredContent.audit.source.endpoint, /limit=20/);
  assert.match(result.structuredContent.audit.source.endpoint, /vmid=100/);
  assert.equal(result.structuredContent.audit.classification, 'READ');
  assert.equal(result.isError, undefined);
});

test('task failures and logs are bounded, typed, and validate UPIDs', async () => {
  const s = server({ '/cluster/tasks': [{ status: 'stopped', exitstatus: 'ERROR' }], '/nodes/pve1/tasks/': [{ n: 1, t: 'safe' }] });
  const failures = await s.auditReaders.handle('proxmox_audit_task_failures', { limit: 5 });
  assert.equal(failures.structuredContent.status, 'failed');
  const upid = 'UPID:pve1:0000ABCD:12345678:5F3A1B2C:vzdump:100:root@pam:';
  const log = await s.auditReaders.handle('proxmox_get_task_log', { node: 'pve1', upid, limit: 10 });
  assert.equal(log.structuredContent.entries.length, 1);
  const invalid = await s.auditReaders.handle('proxmox_get_task_log', { node: 'pve1', upid: 'bad' });
  assert.equal(invalid.isError, true);
  assert.equal(invalid.structuredContent.audit.error.category, 'internal');
});

test('backup coverage separates policy from observed artifacts and reports partial data', async () => {
  const denied = Object.assign(new Error('denied'), { statusCode: 403 });
  const s = server({
    '/cluster/resources': [{ vmid: 100, type: 'qemu', node: 'pve1', name: 'one' }, { vmid: 101, type: 'lxc', node: 'pve1', name: 'two' }],
    '/cluster/backup': [{ id: 'daily', enabled: 1 }],
    '/nodes': [{ node: 'pve1', status: 'online' }],
    '/storage': [{ storage: 'local', content: 'backup' }],
    '/nodes/pve1/storage': denied,
  });
  const result = await s.auditReaders.handle('proxmox_audit_backup_coverage', { max_age_hours: 24 });
  assert.equal(result.structuredContent.policy.jobs.length, 1);
  assert.equal(result.structuredContent.summary.unprotected, 2);
  assert.equal(result.structuredContent.audit.evidence.partial, true);
  assert.equal(result.structuredContent.audit.warnings.length, 1);
});

test('journal uses only official cursor/time/lastentries parameters and represents empty results', async () => {
  const calls = []; const s = server({ '/nodes/pve1/journal': (endpoint) => { calls.push(endpoint); return []; } });
  const result = await s.auditReaders.handle('proxmox_get_node_journal', { node: 'pve1', lastentries: 25, since: 1, startcursor: 'cursor' });
  assert.equal(result.structuredContent.count, 0);
  assert.match(calls[0], /lastentries=25/);
  assert.match(calls[0], /startcursor=cursor/);
  assert.doesNotMatch(calls[0], /(?:\?|&)limit=|(?:\?|&)start=|service=/);
  const invalid = await s.auditReaders.handle('proxmox_get_node_journal', { node: 'bad/node' });
  assert.equal(invalid.isError, true);
});

test('backup coverage detects QEMU and LXC vzdump artifacts, including artifact-only protection', async () => {
  const s = server({
    '/cluster/resources': [{ vmid: 100, type: 'qemu', node: 'pve1' }, { vmid: 101, type: 'lxc', node: 'pve1' }, { vmid: 102, type: 'qemu', node: 'pve1' }],
    '/cluster/backup': [{ id: 'job', enabled: 1, vmids: '102' }],
    '/nodes': [{ node: 'pve1', status: 'online' }],
    '/storage': [{ storage: 'local', content: 'images,backup' }],
    '/nodes/pve1/storage/local/content': [
      { content: 'backup', volid: 'local:backup/vzdump-qemu-100-2026_07_22-10_00_00.vma.zst', ctime: 1784714400 },
      { content: 'backup', volid: 'local:backup/vzdump-lxc-101-2026_07_22-11_00_00.tar.zst', ctime: 1784718000 },
      { content: 'iso', volid: 'local:iso/unrelated.iso' },
    ],
    '/nodes/pve1/storage': [{ storage: 'local', active: 1 }],
  });
  const result = await s.auditReaders.handle('proxmox_audit_backup_coverage', { max_age_hours: 8760 });
  const byId = new Map(result.structuredContent.observed.coverage.map((item) => [item.vmid, item]));
  assert.equal(byId.get(100).guest_type, 'qemu'); assert.equal(byId.get(100).coverage_status, 'artifact_only');
  assert.equal(byId.get(101).guest_type, 'lxc'); assert.equal(byId.get(101).artifact_count, 1);
  assert.equal(byId.get(102).coverage_status, 'scheduled_policy_only');
  assert.equal(result.structuredContent.summary.artifactCovered, 2);
});

test('network comment update reads first, changes only comments, and never reloads networking', async () => {
  const calls = []; const state = { iface: 'vmbr0', type: 'bridge', comments: 'old', bridge_ports: 'eno1', bridge_vlan_aware: 1, address: '192.0.2.2', gateway: '192.0.2.1', mtu: 1500, autostart: 1, bridge_stp: 'off', active: 1 };
  const s = server({});
  s.proxmoxRequest = async (endpoint, method = 'GET', body = null) => { calls.push({ endpoint, method, body }); if (endpoint === '/nodes/pve1/network') return [{ ...state }]; if (method === 'PUT') { state.comments = body.comments ?? ''; return {}; } return {}; };
  const plan = await s.auditReaders.handle('proxmox_update_node_network_comment', { node: 'pve1', iface: 'vmbr0', comment: 'new' });
  assert.equal(plan.structuredContent.dry_run, true); assert.equal(calls.length, 1);
  assert.deepEqual(plan.structuredContent.request.body, { iface: 'vmbr0', type: 'bridge', bridge_ports: 'eno1', bridge_vlan_aware: 1, address: '192.0.2.2', gateway: '192.0.2.1', mtu: 1500, autostart: 1, comments: 'new' });
  s.allowElevated = true;
  const changed = await s.auditReaders.handle('proxmox_update_node_network_comment', { node: 'pve1', iface: 'vmbr0', comment: 'new', dry_run: false, confirm: true });
  const put = calls.find((call) => call.method === 'PUT');
  assert.deepEqual(put.body, plan.structuredContent.request.body); assert.equal(changed.structuredContent.reloadPerformed, false); assert.equal(changed.structuredContent.postcondition_verified, true);
  const clear = await s.auditReaders.handle('proxmox_update_node_network_comment', { node: 'pve1', iface: 'vmbr0', clear_comment: true, dry_run: false, confirm: true });
  assert.equal(clear.structuredContent.after.comments, '');
  assert.deepEqual(calls.filter((call) => call.method === 'PUT')[1].body, { iface: 'vmbr0', type: 'bridge', bridge_ports: 'eno1', bridge_vlan_aware: 1, address: '192.0.2.2', gateway: '192.0.2.1', mtu: 1500, autostart: 1, delete: ['comments'] });
});

test('network comment serializer converts a read-form CIDR prefix to the API netmask form', () => {
  const s = server({});
  assert.equal(s.auditReaders.networkNetmask({ cidr: '192.168.0.201/24', netmask: '24' }), '255.255.255.0');
  assert.equal(s.auditReaders.networkNetmask({ cidr: '10.0.0.1/16', netmask: '16' }), '255.255.0.0');
});

test('bridge multicast snooping update is bridge-only, dry-run by default, and reloads only on explicit acknowledgement', async () => {
  const calls = []; const state = { iface: 'WAN', type: 'bridge', bridge_ports: 'nic4', autostart: 1, options: ['bridge-mcsnoop 1'], active: 1 };
  const s = server({});
  s.proxmoxRequest = async (endpoint, method = 'GET', body = null) => {
    calls.push({ endpoint, method, body });
    if (endpoint === '/nodes/pve1/network' && method === 'GET') return [{ ...state }];
    if (endpoint === '/nodes/pve1/network/WAN' && method === 'PUT') { state.options = body.options; return {}; }
    if (endpoint === '/nodes/pve1/network' && method === 'PUT') return {};
    throw new Error(`unexpected request ${method} ${endpoint}`);
  };
  const plan = await s.auditReaders.handle('proxmox_set_bridge_multicast_snooping', { node: 'pve1', iface: 'WAN', enabled: false });
  assert.equal(plan.structuredContent.dry_run, true);
  assert.deepEqual(plan.structuredContent.after.options, ['bridge-mcsnoop 0']);
  assert.equal(calls.some((call) => call.method === 'PUT'), false);
  s.allowElevated = true;
  const changed = await s.auditReaders.handle('proxmox_set_bridge_multicast_snooping', { node: 'pve1', iface: 'WAN', enabled: false, dry_run: false, confirm: true });
  assert.equal(changed.structuredContent.postcondition_verified, true);
  assert.equal(changed.structuredContent.reloadPerformed, false);
  const applied = await s.auditReaders.handle('proxmox_set_bridge_multicast_snooping', { node: 'pve1', iface: 'WAN', enabled: true, dry_run: false, confirm: true, apply_network: true, confirm_network_reload: true });
  assert.equal(applied.structuredContent.reloadPerformed, true);
  assert.equal(calls.some((call) => call.endpoint === '/nodes/pve1/network' && call.method === 'PUT'), true);
  const notBridge = await s.auditReaders.handle('proxmox_set_bridge_multicast_snooping', { node: 'pve1', iface: 'WAN', enabled: false, dry_run: false, confirm: true, apply_network: true });
  assert.equal(notBridge.isError, true);
});

test('SDN VNet writes are dry-run by default, validate VLANs, prevent duplicate and in-use deletion', async () => {
  const calls = []; let exists = false; const s = server({}); s.allowElevated = true;
  s.proxmoxRequest = async (endpoint, method = 'GET', body = null) => {
    calls.push({ endpoint, method, body });
    if (endpoint === '/cluster/sdn/vnets') return exists ? [{ vnet: 'demo', zone: 'zone1' }] : [];
    if (endpoint === '/cluster/sdn/zones') return [{ zone: 'zone1' }];
    if (endpoint === '/cluster/sdn/vnets?pending=1' || endpoint === '/cluster/sdn/vnets?running=1') return [];
    if (endpoint === '/cluster/resources?type=vm') return [{ node: 'pve1', type: 'qemu', vmid: 100 }];
    if (endpoint.includes('/qemu/100/config')) return { net0: 'virtio=aa:bb:cc:dd:ee:ff,bridge=demo' };
    return {};
  };
  const plan = await s.auditReaders.handle('proxmox_create_sdn_vnet', { vnet: 'demo', zone: 'zone1', vlan_tag: 10 });
  assert.equal(plan.structuredContent.dry_run, true); assert.equal(calls.some((call) => call.method === 'POST'), false);
  exists = true;
  const invalid = await s.auditReaders.handle('proxmox_create_sdn_vnet', { vnet: 'demo', zone: 'zone1', vlan_tag: 4095 });
  assert.equal(invalid.isError, true);
  const invalidName = await s.auditReaders.handle('proxmox_create_sdn_vnet', { vnet: 'invalid-name', zone: 'zone1', vlan_tag: 10 });
  assert.equal(invalidName.isError, true);
  const deletion = await s.auditReaders.handle('proxmox_delete_sdn_vnet', { vnet: 'demo' });
  assert.equal(deletion.isError, true); assert.equal(deletion.structuredContent.error.category, 'conflict');
});

test('SDN VNet identifiers and aliases follow the official backend contract', async () => {
  const s = server({});
  assert.equal(s.auditReaders.validateVnet('network'), 'network');
  assert.equal(s.auditReaders.validateVnet('ab'), 'ab');
  for (const invalid of ['a', 'network10', 'net_work', 'net-work', '1network']) {
    assert.throws(() => s.auditReaders.validateVnet(invalid), /Invalid Proxmox VNet ID/);
  }
  assert.equal(s.auditReaders.validateVnetAlias('NETWORKING (VLAN 10)'), 'NETWORKING (VLAN 10)');
  assert.equal(s.auditReaders.validateVnetAlias('x'.repeat(256)), 'x'.repeat(256));
  assert.throws(() => s.auditReaders.validateVnetAlias('x'.repeat(257)), /Invalid VNet alias/);
  assert.throws(() => s.auditReaders.validateVnetAlias('alias/unsupported'), /Invalid VNet alias/);
});

test('SDN readers distinguish technical IDs from the alias display field without inventing descriptions', async () => {
  const s = server({ '/cluster/sdn/vnets': [{ vnet: 'network', alias: 'NETWORKING' }] });
  const listed = await s.auditReaders.handle('proxmox_list_sdn_vnets', {});
  assert.deepEqual(listed.structuredContent.vnet_identity, [{ id: 'network', alias: 'NETWORKING', description: null, display_name: 'NETWORKING' }]);
  const state = await s.auditReaders.handle('proxmox_get_sdn_vnet_state', {});
  assert.deepEqual(state.structuredContent.pending_identity, [{ id: 'network', alias: 'NETWORKING', description: null, display_name: 'NETWORKING' }]);
  assert.deepEqual(state.structuredContent.running_identity, [{ id: 'network', alias: 'NETWORKING', description: null, display_name: 'NETWORKING' }]);
  assert.equal(state.structuredContent.has_pending_changes, false);
});

test('SDN pending-state comparison is insensitive to API object-key ordering', async () => {
  const s = server({});
  s.proxmoxRequest = async (endpoint) => {
    if (endpoint === '/cluster/sdn/vnets?pending=1') return [{ vnet: 'network', zone: 'home', tag: 10, alias: 'NETWORKING' }];
    if (endpoint === '/cluster/sdn/vnets?running=1') return [{ alias: 'NETWORKING', tag: 10, zone: 'home', vnet: 'network' }];
    throw new Error(`unexpected endpoint ${endpoint}`);
  };
  const state = await s.auditReaders.handle('proxmox_get_sdn_vnet_state', {});
  assert.equal(state.structuredContent.has_pending_changes, false);
});

test('cluster audit returns a successful not-configured result with partial warnings', async () => {
  const unavailable = Object.assign(new Error('not found'), { statusCode: 404 });
  const s = server({ '/cluster/status': [], '/cluster/config/totem': unavailable, '/cluster/config/qdevice': unavailable, '/cluster/ha/status/current': [] });
  const result = await s.auditReaders.handle('proxmox_audit_cluster_state', {});
  assert.equal(result.structuredContent.configured, false);
  assert.equal(result.structuredContent.audit.evidence.partial, true);
});

test('node repository, certificate, disk, and network readers use validated node REST paths', async () => {
  const s = server({
    '/nodes/pve1/apt/repositories': [{ path: '/etc/apt/sources.list', enabled: 1 }],
    '/nodes/pve1/certificates/info': [{ filename: 'pveproxy-ssl.pem', notafter: new Date(Date.now() + 86400000).toISOString() }],
    '/nodes/pve1/disks/list': [{ devpath: '/dev/sda' }],
    '/nodes/pve1/network': [{ iface: 'vmbr0', type: 'bridge' }],
  });
  assert.equal((await s.auditReaders.handle('proxmox_list_node_repositories', { node: 'pve1' })).structuredContent.repositories.length, 1);
  assert.equal((await s.auditReaders.handle('proxmox_audit_certificate_expiry', { node: 'pve1', warning_days: 30 })).structuredContent.certificates[0].expiring, true);
  assert.equal((await s.auditReaders.handle('proxmox_list_node_disks', { node: 'pve1' })).structuredContent.disks[0].devpath, '/dev/sda');
  const network = await s.auditReaders.handle('proxmox_list_node_network', { node: 'pve1' });
  assert.equal(network.structuredContent.interfaces[0].iface, 'vmbr0');
  assert.equal(network.structuredContent.observed_state[0].cable_destination, 'unknown');
  assert.equal(network.structuredContent.observed_state[0].negotiated_speed, 'unknown');
});

test('SMART reader rejects command/path injection and only invokes its API endpoint', async () => {
  const s = server({ '/nodes/pve1/disks/smart': { health: 'PASSED' } });
  const invalid = await s.auditReaders.handle('proxmox_get_disk_smart', { node: 'pve1', disk: 'sda;rm -rf /' });
  assert.equal(invalid.isError, true);
  const valid = await s.auditReaders.handle('proxmox_get_disk_smart', { node: 'pve1', disk: 'sda' });
  assert.equal(valid.structuredContent.disk, '/dev/sda');
  assert.match(valid.structuredContent.audit.source.endpoint, /disk=%2Fdev%2Fsda/);
});

test('access control aggregation returns partial permission gaps without token secrets', async () => {
  const denied = Object.assign(new Error('permission denied'), { statusCode: 403 });
  const s = server({
    '/access/users/audit%40pam/token': denied, '/access/users': [{ userid: 'audit@pam' }], '/access/groups': [], '/access/roles': [], '/access/acl': [{ path: '/', roleid: 'Administrator', ugid: 'audit@pam' }], '/access/domains': [],
  });
  const result = await s.auditReaders.handle('proxmox_list_access_control', {});
  assert.equal(result.structuredContent.users.length, 1);
  assert.equal(result.structuredContent.audit.evidence.partial, true);
  assert.doesNotMatch(JSON.stringify(result.structuredContent), /test-token/);
});

test('Ceph absence is a successful structured result rather than an internal error', async () => {
  const absent = Object.assign(new Error('not configured'), { statusCode: 404 });
  const s = server({ '/cluster/ceph/status': absent });
  const result = await s.auditReaders.handle('proxmox_get_ceph_status', {});
  assert.equal(result.structuredContent.configured, false);
  assert.equal(result.isError, undefined);
});
