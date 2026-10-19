import { isIP } from 'node:net';
import { ProxmoxMcpError, errorFromUnknown, parseBoundedInteger } from './foundation.js';

const PAGE = { limit: { type: 'number', minimum: 1, maximum: 200 }, start: { type: 'number', minimum: 0 } };
const nodeSchema = { node: { type: 'string' } };

export const auditToolDefinitions = [
  ['proxmox_list_tasks', 'List recent cluster or node tasks with bounded pagination and filters.', { ...PAGE, ...nodeSchema, status: { type: 'string', enum: ['all', 'failed', 'running'] }, type: { type: 'string' }, user: { type: 'string' }, vmid: { type: 'string' }, since: { type: 'number' }, until: { type: 'number' } }],
  ['proxmox_audit_task_failures', 'Summarize recent failed Proxmox tasks without retrieving task logs.', { ...PAGE, ...nodeSchema, since: { type: 'number' } }],
  ['proxmox_get_task_log', 'Read a bounded, paginated task log by node and UPID.', { ...PAGE, ...nodeSchema, upid: { type: 'string' } }, ['node', 'upid']],
  ['proxmox_list_backup_jobs', 'List configured Proxmox backup jobs and schedules.', {}],
  ['proxmox_audit_backup_coverage', 'Compare scheduled backup policy with actual vzdump backup artifacts and guest inventory.', { max_age_hours: { type: 'number', minimum: 1, maximum: 8760 } }],
  ['proxmox_audit_cluster_state', 'Read cluster, quorum, Corosync, QDevice, and HA state with partial-result warnings.', {}],
  ['proxmox_list_ha_groups', 'List Proxmox HA groups.', {}],
  ['proxmox_get_ha_status', 'Read current Proxmox HA manager state.', {}],
  ['proxmox_list_replication_jobs', 'List configured Proxmox storage replication jobs.', {}],
  ['proxmox_list_node_repositories', 'List configured APT repositories for a node.', nodeSchema, ['node']],
  ['proxmox_list_node_packages', 'List Proxmox package versions and update metadata for a node.', nodeSchema, ['node']],
  ['proxmox_get_node_version', 'Read Proxmox node version and kernel metadata.', nodeSchema, ['node']],
  ['proxmox_get_node_subscription', 'Read node subscription status without exposing subscription keys.', nodeSchema, ['node']],
  ['proxmox_list_node_certificates', 'List node certificate metadata and fingerprints.', nodeSchema, ['node']],
  ['proxmox_audit_certificate_expiry', 'Audit node certificate expiration against a bounded warning threshold.', { ...nodeSchema, warning_days: { type: 'number', minimum: 1, maximum: 3650 } }, ['node']],
  ['proxmox_get_node_report', 'Read the official bounded Proxmox node diagnostic report.', nodeSchema, ['node']],
  ['proxmox_get_node_dns', 'Read the node DNS configuration managed by Proxmox (the authoritative API representation of /etc/resolv.conf).', nodeSchema, ['node']],
  ['proxmox_list_access_control', 'List users, groups, roles, ACLs, realms, and API-token metadata without secrets.', {}],
  ['proxmox_audit_access_control', 'Summarize factual broad ACL and API-token privilege-separation findings.', {}],
  ['proxmox_list_node_disks', 'List physical disk inventory exposed by the Proxmox API.', nodeSchema, ['node']],
  ['proxmox_get_disk_smart', 'Read SMART data for one strictly validated disk identifier.', { ...nodeSchema, disk: { type: 'string' } }, ['node', 'disk']],
  ['proxmox_list_zfs_pools', 'List ZFS pools exposed by the Proxmox API.', nodeSchema, ['node']],
  ['proxmox_list_lvm', 'List LVM volume groups exposed by the Proxmox API.', nodeSchema, ['node']],
  ['proxmox_list_lvmthin', 'List LVM-thin pools exposed by the Proxmox API.', nodeSchema, ['node']],
  ['proxmox_audit_storage_health', 'Combine configured storage and node storage availability with partial-result warnings.', {}],
  ['proxmox_list_node_network', 'List node interfaces, bridges, bonds, VLAN configuration, addresses, and MTU.', nodeSchema, ['node']],
  ['proxmox_list_sdn_zones', 'List Proxmox SDN zones.', {}],
  ['proxmox_list_sdn_vnets', 'List Proxmox SDN VNets.', {}],
  ['proxmox_list_sdn_ipams', 'List Proxmox SDN IPAM configuration.', {}],
  ['proxmox_audit_network_state', 'Combine node network and SDN inventory with partial-result warnings.', { ...nodeSchema }],
  ['proxmox_get_node_journal', 'Read bounded official node journal entries. Proxmox journal pagination uses cursors, not start/limit.', { ...nodeSchema, lastentries: { type: 'number', minimum: 1, maximum: 200 }, since: { type: 'number' }, until: { type: 'number' }, startcursor: { type: 'string', minLength: 1, maxLength: 1024 }, endcursor: { type: 'string', minLength: 1, maxLength: 1024 } }, ['node']],
  ['proxmox_list_node_services', 'List Proxmox node service state.', nodeSchema, ['node']],
  ['proxmox_get_ceph_status', 'Detect Ceph and return health only when it is configured.', {}],
].map(([name, description, properties, required = []]) => ({ name, description: `${description} READ-only audit reader.`, inputSchema: { type: 'object', properties, required }, annotations: { readOnlyHint: true } }));

// These narrowly scoped configuration tools deliberately live beside the SDN
// and network readers so their read-before-write evidence remains consistent.
// They are not a generic Proxmox API escape hatch.
export const managementToolDefinitions = [
  ['proxmox_update_node_dns', 'Update only explicitly supplied node DNS fields through the Proxmox API. It changes the Proxmox-managed DNS configuration immediately; it does not reload networking or reboot the node.', {
    node: { type: 'string' }, dns1: { type: 'string', maxLength: 45 }, dns2: { type: 'string', maxLength: 45 }, dns3: { type: 'string', maxLength: 45 }, search: { type: 'string', maxLength: 253 }, clear_dns1: { type: 'boolean', default: false }, clear_dns2: { type: 'boolean', default: false }, clear_dns3: { type: 'boolean', default: false }, clear_search: { type: 'boolean', default: false }, allow_empty_dns: { type: 'boolean', default: false }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false },
  }, ['node']],
  ['proxmox_update_node_network_comment', 'Update only the comments field of an existing node network interface. The change is staged; this tool never reloads networking.', {
    node: { type: 'string' }, iface: { type: 'string', minLength: 1, maxLength: 15 }, comment: { type: 'string', maxLength: 2048 }, clear_comment: { type: 'boolean', default: false }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false },
  }, ['node', 'iface']],
  ['proxmox_set_bridge_multicast_snooping', 'Enable or disable Linux bridge multicast snooping (bridge-mcsnoop) on one existing Proxmox bridge. The configuration is staged by default; optional network reload requires separate explicit acknowledgement.', {
    node: { type: 'string' }, iface: { type: 'string', minLength: 1, maxLength: 15 }, enabled: { type: 'boolean' }, apply_network: { type: 'boolean', default: false }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false }, confirm_network_reload: { type: 'boolean', default: false },
  }, ['node', 'iface', 'enabled']],
  ['proxmox_get_sdn_vnet_state', 'Compare pending and running Proxmox SDN VNet configuration. A VNet ID is a Proxmox technical identifier (2-8 alphanumeric characters); alias is the separate human-readable field.', { vnet: { type: 'string', minLength: 2, maxLength: 8, pattern: '^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$' } }],
  ['proxmox_create_sdn_vnet', 'Create one Proxmox SDN VNet configuration. The configuration remains pending until explicitly applied.', {
    vnet: { type: 'string', minLength: 2, maxLength: 8, pattern: '^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$' }, zone: { type: 'string', minLength: 1, maxLength: 60 }, vlan_tag: { type: 'number', minimum: 1, maximum: 4094 }, alias: { type: 'string', maxLength: 256, pattern: '^[()\\-_.\\w\\d\\s]{0,256}$' }, vlan_aware: { type: 'boolean' }, isolate_ports: { type: 'boolean' }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false },
  }, ['vnet', 'zone']],
  ['proxmox_update_sdn_vnet', 'Update explicitly supplied fields of one existing Proxmox SDN VNet. It never bulk-replaces VNet configuration.', {
    vnet: { type: 'string', minLength: 2, maxLength: 8, pattern: '^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$' }, zone: { type: 'string', minLength: 1, maxLength: 60 }, vlan_tag: { type: 'number', minimum: 1, maximum: 4094 }, alias: { type: 'string', maxLength: 256, pattern: '^[()\\-_.\\w\\d\\s]{0,256}$' }, vlan_aware: { type: 'boolean' }, isolate_ports: { type: 'boolean' }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false },
  }, ['vnet']],
  ['proxmox_delete_sdn_vnet', 'Delete one unused Proxmox SDN VNet configuration. Refuses deletion while a guest references the VNet.', { vnet: { type: 'string', minLength: 2, maxLength: 8, pattern: '^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$' }, dry_run: { type: 'boolean', default: true }, confirm: { type: 'boolean', default: false } }, ['vnet']],
  ['proxmox_apply_sdn_configuration', 'Apply all pending SDN changes. Proxmox performs a network reload; explicit acknowledgement is required.', { dry_run: { type: 'boolean', default: true }, confirm_apply_all_pending: { type: 'boolean', default: false }, confirm_network_reload: { type: 'boolean', default: false } }],
].map(([name, description, properties, required = []]) => ({ name, description: `${description} WRITE operation; requires PROXMOX_ALLOW_ELEVATED=true and explicit confirmation.`, inputSchema: { type: 'object', additionalProperties: false, properties, required }, annotations: { readOnlyHint: false } }));

export class AuditReaders {
  constructor(server) { this.server = server; }

  page(args) {
    return { limit: parseBoundedInteger(args.limit, { name: 'limit', defaultValue: 50, min: 1, max: 200 }), start: parseBoundedInteger(args.start, { name: 'start', defaultValue: 0, min: 0, max: 100000 }) };
  }
  query(values) { return Object.entries(values).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'); }
  endpoint(path, values) { const query = this.query(values); return query ? `${path}?${query}` : path; }
  validateNode(args) { return this.server.validateNodeName(args.node); }
  validateDisk(disk) {
    if (typeof disk !== 'string' || !/^(?:\/dev\/)?(?:sd[a-z]+|vd[a-z]+|nvme\d+n\d+)$/i.test(disk)) throw new Error('Invalid disk identifier. Expected /dev/sdX, /dev/vdX, or /dev/nvmeNnN.');
    return disk.startsWith('/dev/') ? disk : `/dev/${disk}`;
  }
  async safe(endpoint, warnings, label) {
    try { return await this.server.proxmoxRequest(endpoint); }
    catch (error) {
      const typed = errorFromUnknown(error, endpoint);
      warnings.push({ code: typed.code, category: typed.category, endpoint, label, message: typed.message, statusCode: typed.statusCode ?? null });
      return undefined;
    }
  }
  result(tool, data, { endpoint, node, warnings = [], partial = false } = {}) {
    return this.server.respond(JSON.stringify(data, null, 2), data, false, { tool, source: { type: 'proxmox-api', endpoint, ...(node ? { node } : {}) }, warnings, partial: partial || warnings.length > 0 });
  }
  unavailable(tool, code, message, endpoint) {
    return this.result(tool, { configured: false, unavailable: true }, { endpoint, warnings: [{ code, message }], partial: true });
  }
  async handle(name, args = {}) {
    try { return await this.handleUnsafe(name, args); }
    catch (error) { return this.server.toolError(name, error); }
  }
  async handleUnsafe(name, args = {}) {
    switch (name) {
        case 'proxmox_list_tasks': return this.listTasks(name, args);
        case 'proxmox_audit_task_failures': return this.taskFailures(name, args);
        case 'proxmox_get_task_log': return this.taskLog(name, args);
        case 'proxmox_list_backup_jobs': return this.result(name, { jobs: await this.server.proxmoxRequest('/cluster/backup') || [] }, { endpoint: '/cluster/backup' });
        case 'proxmox_audit_backup_coverage': return this.backupCoverage(name, args);
        case 'proxmox_audit_cluster_state': return this.clusterState(name);
        case 'proxmox_list_ha_groups': return this.result(name, { groups: await this.server.proxmoxRequest('/cluster/ha/groups') || [] }, { endpoint: '/cluster/ha/groups' });
        case 'proxmox_get_ha_status': return this.result(name, { status: await this.server.proxmoxRequest('/cluster/ha/status/current') || [] }, { endpoint: '/cluster/ha/status/current' });
        case 'proxmox_list_replication_jobs': return this.result(name, { jobs: await this.server.proxmoxRequest('/cluster/replication') || [] }, { endpoint: '/cluster/replication' });
        case 'proxmox_list_node_repositories': return this.nodePath(name, args, 'apt/repositories', 'repositories');
        case 'proxmox_list_node_packages': return this.nodePath(name, args, 'apt/versions', 'packages');
        case 'proxmox_get_node_version': return this.nodePath(name, args, 'version', 'version');
        case 'proxmox_get_node_subscription': return this.nodePath(name, args, 'subscription', 'subscription');
        case 'proxmox_list_node_certificates': return this.nodePath(name, args, 'certificates/info', 'certificates');
        case 'proxmox_audit_certificate_expiry': return this.certificateExpiry(name, args);
        case 'proxmox_get_node_report': return this.nodePath(name, args, 'report', 'report');
        case 'proxmox_get_node_dns': return this.nodeDns(name, args);
        case 'proxmox_list_access_control': return this.accessControl(name);
        case 'proxmox_audit_access_control': return this.accessAudit(name);
        case 'proxmox_list_node_disks': return this.nodePath(name, args, 'disks/list', 'disks');
        case 'proxmox_get_disk_smart': return this.diskSmart(name, args);
        case 'proxmox_list_zfs_pools': return this.nodePath(name, args, 'disks/zfs', 'pools');
        case 'proxmox_list_lvm': return this.nodePath(name, args, 'disks/lvm', 'volumeGroups');
        case 'proxmox_list_lvmthin': return this.nodePath(name, args, 'disks/lvmthin', 'thinPools');
        case 'proxmox_audit_storage_health': return this.storageHealth(name);
        case 'proxmox_list_node_network': return this.nodeNetwork(name, args);
        case 'proxmox_list_sdn_zones': return this.result(name, { zones: await this.server.proxmoxRequest('/cluster/sdn/zones') || [] }, { endpoint: '/cluster/sdn/zones' });
        case 'proxmox_list_sdn_vnets': { const vnets = await this.server.proxmoxRequest('/cluster/sdn/vnets') || []; return this.result(name, { vnets, vnet_identity: this.vnetIdentity(vnets) }, { endpoint: '/cluster/sdn/vnets' }); }
        case 'proxmox_list_sdn_ipams': return this.result(name, { ipams: await this.server.proxmoxRequest('/cluster/sdn/ipams') || [] }, { endpoint: '/cluster/sdn/ipams' });
        case 'proxmox_audit_network_state': return this.networkState(name, args);
        case 'proxmox_get_node_journal': return this.journal(name, args);
        case 'proxmox_list_node_services': return this.nodePath(name, args, 'services', 'services');
        case 'proxmox_get_ceph_status': return this.cephStatus(name);
        case 'proxmox_update_node_network_comment': return this.updateNetworkComment(name, args);
        case 'proxmox_set_bridge_multicast_snooping': return this.setBridgeMulticastSnooping(name, args);
        case 'proxmox_update_node_dns': return this.updateNodeDns(name, args);
        case 'proxmox_get_sdn_vnet_state': return this.vnetState(name, args);
        case 'proxmox_create_sdn_vnet': return this.createVnet(name, args);
        case 'proxmox_update_sdn_vnet': return this.updateVnet(name, args);
        case 'proxmox_delete_sdn_vnet': return this.deleteVnet(name, args);
        case 'proxmox_apply_sdn_configuration': return this.applySdn(name, args);
        default: throw new Error(`Unknown audit reader: ${name}`);
    }
  }
  async nodePath(tool, args, suffix, key) {
    const node = this.validateNode(args); const endpoint = `/nodes/${node}/${suffix}`;
    return this.result(tool, { [key]: await this.server.proxmoxRequest(endpoint) }, { endpoint, node });
  }
  async nodeDns(tool, args) {
    const node = this.validateNode(args); const endpoint = `/nodes/${node}/dns`;
    const dns = this.normalizeDns(await this.server.proxmoxRequest(endpoint) || {});
    return this.result(tool, { dns, managed_by: 'proxmox-api', file: '/etc/resolv.conf' }, { endpoint, node });
  }
  async nodeNetwork(tool, args) {
    const node = this.validateNode(args); const endpoint = `/nodes/${node}/network`; const interfaces = await this.server.proxmoxRequest(endpoint) || [];
    // The REST endpoint is authoritative for configured/live fields it returns,
    // but does not establish cable destination, switch port, USB ordinal, or
    // ethtool-only capabilities. Do not turn intended design into evidence.
    const observed_state = interfaces.map((entry) => ({
      iface: entry.iface, type: entry.type, active: entry.active ?? null,
      autostart: entry.autostart ?? null, mtu: entry.mtu ?? null,
      bridge_ports: entry.bridge_ports ?? null, mac: entry.mac ?? entry.hwaddr ?? null,
      negotiated_speed: entry.speed ?? 'unknown', duplex: entry.duplex ?? 'unknown',
      supported_link_modes: 'unknown', cable_destination: 'unknown', switch_port: 'unknown', usb_adapter_ordinal: 'unknown',
    }));
    return this.result(tool, { interfaces, observed_state, limitations: ['Physical cable destination, switch port, USB adapter ordinal, and link capabilities require physical or host-console verification when not returned by the Proxmox REST API.'] }, { endpoint, node });
  }
  async listTasks(tool, args) {
    const { limit, start } = this.page(args); const node = args.node ? this.validateNode(args) : null;
    const status = args.status || 'all';
    const endpoint = this.endpoint(node ? `/nodes/${node}/tasks` : '/cluster/tasks', { limit, start, ...(status === 'failed' ? { errors: 1 } : {}), ...(args.type ? { typefilter: args.type } : {}), ...(args.user ? { userfilter: args.user } : {}), ...(args.vmid ? { vmid: this.server.validateVMID(args.vmid) } : {}), since: args.since, until: args.until });
    const tasks = await this.server.proxmoxRequest(endpoint) || [];
    const filtered = status === 'running' ? tasks.filter((task) => task.status === 'running') : tasks;
    return this.result(tool, { tasks: filtered, page: { limit, start, count: filtered.length }, status }, { endpoint, node });
  }
  async taskFailures(tool, args) { return this.listTasks(tool, { ...args, status: 'failed' }); }
  async taskLog(tool, args) {
    const node = this.validateNode(args); const upid = this.server.validateUPID(args.upid); const { limit, start } = this.page(args);
    const endpoint = this.endpoint(`/nodes/${node}/tasks/${encodeURIComponent(upid)}/log`, { limit, start });
    const entries = await this.server.proxmoxRequest(endpoint) || [];
    return this.result(tool, { node, upid, entries, page: { limit, start, count: entries.length } }, { endpoint, node });
  }
  async backupCoverage(tool, args) {
    const warnings = []; const maxAgeHours = parseBoundedInteger(args.max_age_hours, { name: 'max_age_hours', defaultValue: 48, min: 1, max: 8760 });
    const [guests, jobs, nodes, configuredStorage] = await Promise.all([
      this.safe('/cluster/resources?type=vm', warnings, 'guest inventory'), this.safe('/cluster/backup', warnings, 'backup jobs'),
      this.safe('/nodes', warnings, 'node inventory'), this.safe('/storage', warnings, 'storage configuration'),
    ]);
    const artifacts = await this.backupArtifacts(nodes || [], configuredStorage || [], warnings);
    const byGuest = new Map();
    for (const artifact of artifacts) {
      const key = `${artifact.guest_type}:${artifact.vmid}`;
      const existing = byGuest.get(key) || [];
      existing.push(artifact); byGuest.set(key, existing);
    }
    const now = Date.now();
    const coverage = (guests || []).filter((g) => g.type === 'qemu' || g.type === 'lxc').map((guest) => {
      const guestArtifacts = (byGuest.get(`${guest.type}:${guest.vmid}`) || []).sort((a, b) => (b.timestamp_epoch || 0) - (a.timestamp_epoch || 0));
      const latest = guestArtifacts[0] || null;
      const scheduledPolicy = this.guestHasScheduledPolicy(guest, jobs || []);
      const ageHours = latest?.timestamp_epoch ? (now - latest.timestamp_epoch * 1000) / 3600000 : null;
      const hasRecentBackup = ageHours !== null && ageHours <= maxAgeHours;
      const coverage_status = latest ? (scheduledPolicy ? 'scheduled_and_artifact' : 'artifact_only') : (scheduledPolicy ? 'scheduled_policy_only' : 'unprotected');
      return { vmid: guest.vmid, guest_type: guest.type, node: guest.node, name: guest.name || null, scheduled_policy: scheduledPolicy, artifact_count: guestArtifacts.length, latest_backup: latest?.timestamp || null, latest_artifact: latest, has_backup_artifact: Boolean(latest), has_recent_backup: hasRecentBackup, backup_age_hours: ageHours, coverage_status };
    });
    return this.result(tool, { policy: { jobs: jobs || [] }, observed: { artifacts, coverage }, summary: { guests: coverage.length, scheduledPolicy: coverage.filter((g) => g.scheduled_policy).length, artifactCovered: coverage.filter((g) => g.has_backup_artifact).length, recentArtifactCovered: coverage.filter((g) => g.has_recent_backup).length, unprotected: coverage.filter((g) => g.coverage_status === 'unprotected').length, maxAgeHours } }, { endpoint: ['/cluster/resources?type=vm', '/cluster/backup', '/nodes', '/storage', '/nodes/{node}/storage/{storage}/content?content=backup'], warnings, partial: warnings.length > 0 });
  }
  guestHasScheduledPolicy(guest, jobs) {
    return jobs.some((job) => {
      if (job.enabled === 0 || job.enabled === false) return false;
      const selected = Array.isArray(job.vmids) ? job.vmids.map(String) : String(job.vmids || '').split(',').map((id) => id.trim()).filter(Boolean);
      const excluded = Array.isArray(job.exclude) ? job.exclude.map(String) : String(job.exclude || '').split(',').map((id) => id.trim()).filter(Boolean);
      if (excluded.includes(String(guest.vmid))) return false;
      return job.all === 1 || job.all === true || selected.includes(String(guest.vmid));
    });
  }
  parseBackupArtifact(item, node, storage) {
    if (!item || typeof item !== 'object' || (item.content && item.content !== 'backup')) return null;
    const source = String(item.volid || item.volume || item.path || '');
    const match = source.match(/vzdump-(qemu|lxc)-(\d+)-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})(?:\.(?:vma|tar)(?:\.(?:zst|gz|lzo))?)?$/i);
    const guestType = match?.[1]?.toLowerCase(); const vmid = match?.[2] || (item.vmid !== undefined ? String(item.vmid) : null);
    if (!vmid || !['qemu', 'lxc'].includes(guestType || item.guest_type)) return null;
    const type = guestType || item.guest_type;
    const filenameTime = match?.[3] ? (() => { const [date, time] = match[3].split('-'); return Date.parse(`${date.replaceAll('_', '-')}T${time.replaceAll('_', ':')}Z`) / 1000; })() : null;
    const epoch = Number(item.ctime || item.timestamp || filenameTime || 0) || null;
    return { vmid: Number(vmid), guest_type: type, storage, node, volid: source, format: item.format || null, size: item.size ?? null, timestamp_epoch: epoch, timestamp: epoch ? new Date(epoch * 1000).toISOString() : null };
  }
  async backupArtifacts(nodes, configuredStorage, warnings) {
    const configured = new Map((configuredStorage || []).filter((s) => String(s.content || '').split(',').includes('backup')).map((s) => [s.storage, s]));
    const locations = new Set(); const items = [];
    for (const nodeInfo of nodes.filter((node) => node.status === 'online' && node.node)) {
      const node = this.server.validateNodeName(nodeInfo.node);
      const storageList = await this.safe(`/nodes/${node}/storage`, warnings, `storage inventory ${node}`) || [];
      for (const storageInfo of storageList) {
        const storage = storageInfo.storage;
        if (!storage || (configured.size && !configured.has(storage)) || storageInfo.active === 0) continue;
        const location = `${node}:${storage}`; if (locations.has(location)) continue; locations.add(location);
        const endpoint = this.endpoint(`/nodes/${node}/storage/${encodeURIComponent(storage)}/content`, { content: 'backup' });
        const content = await this.safe(endpoint, warnings, `backup artifacts ${location}`) || [];
        for (const entry of content) { const artifact = this.parseBackupArtifact(entry, node, storage); if (artifact) items.push(artifact); }
      }
    }
    return items;
  }
  async clusterState(tool) { const warnings = []; const [status, totem, qdevice, ha] = await Promise.all([this.safe('/cluster/status', warnings, 'cluster status'), this.safe('/cluster/config/totem', warnings, 'corosync configuration'), this.safe('/cluster/config/qdevice', warnings, 'qdevice'), this.safe('/cluster/ha/status/current', warnings, 'HA status')]); return this.result(tool, { configured: Array.isArray(status) ? status.some((x) => x.type === 'cluster') : Boolean(status), status: status || [], corosync: totem || null, qdevice: qdevice || null, ha: ha || [] }, { endpoint: ['/cluster/status', '/cluster/config/totem', '/cluster/config/qdevice', '/cluster/ha/status/current'], warnings, partial: warnings.length > 0 }); }
  async certificateExpiry(tool, args) { const node = this.validateNode(args); const warningDays = parseBoundedInteger(args.warning_days, { name: 'warning_days', defaultValue: 30, min: 1, max: 3650 }); const endpoint = `/nodes/${node}/certificates/info`; const certificates = await this.server.proxmoxRequest(endpoint) || []; const now = Date.now(); return this.result(tool, { warningDays, certificates: certificates.map((cert) => ({ ...cert, expiresInDays: cert.notafter ? (new Date(cert.notafter).getTime() - now) / 86400000 : null, expiring: cert.notafter ? (new Date(cert.notafter).getTime() - now) <= warningDays * 86400000 : null })) }, { endpoint, node }); }
  async accessControl(tool) { const warnings = []; const [users, groups, roles, acl, realms] = await Promise.all(['/access/users', '/access/groups', '/access/roles', '/access/acl', '/access/domains'].map((endpoint) => this.safe(endpoint, warnings, endpoint))); const tokens = []; for (const user of users || []) { const id = user.userid; if (!id) continue; const value = await this.safe(`/access/users/${encodeURIComponent(id)}/token`, warnings, `tokens for ${id}`); if (value) tokens.push({ userid: id, tokens: value }); } return this.result(tool, { users: users || [], groups: groups || [], roles: roles || [], acl: acl || [], realms: realms || [], tokens }, { endpoint: ['/access/users', '/access/groups', '/access/roles', '/access/acl', '/access/domains', '/access/users/{userid}/token'], warnings, partial: warnings.length > 0 }); }
  async accessAudit(tool) { const base = await this.accessControl('proxmox_list_access_control'); const data = base.structuredContent; const acl = data.acl || []; const tokens = data.tokens || []; const rootAcl = acl.filter((entry) => entry.path === '/'); const unprivileged = tokens.flatMap((user) => (user.tokens || []).filter((token) => token.privsep === 0 || token.privsep === false).map((token) => ({ userid: user.userid, tokenid: token.tokenid, privsep: token.privsep }))); return this.result(tool, { rootAcl, tokensWithoutPrivilegeSeparation: unprivileged, source: data }, { endpoint: '/access/*', warnings: base.structuredContent.audit.warnings, partial: base.structuredContent.audit.evidence.partial }); }
  async diskSmart(tool, args) { const node = this.validateNode(args); const disk = this.validateDisk(args.disk); const endpoint = this.endpoint(`/nodes/${node}/disks/smart`, { disk }); return this.result(tool, { disk, smart: await this.server.proxmoxRequest(endpoint) }, { endpoint, node }); }
  async storageHealth(tool) { const warnings = []; const nodes = await this.safe('/nodes', warnings, 'nodes') || []; const configured = await this.safe('/storage', warnings, 'storage configuration') || []; const perNode = []; for (const n of nodes.filter((n) => n.status === 'online')) { const endpoint = `/nodes/${this.server.validateNodeName(n.node)}/storage`; const storage = await this.safe(endpoint, warnings, `storage ${n.node}`); if (storage) perNode.push({ node: n.node, storage }); } return this.result(tool, { configured, perNode }, { endpoint: ['/storage', '/nodes/{node}/storage'], warnings, partial: warnings.length > 0 }); }
  async networkState(tool, args) { const warnings = []; const node = args.node ? this.validateNode(args) : null; const [network, zones, vnets, ipams] = await Promise.all([node ? this.safe(`/nodes/${node}/network`, warnings, 'node network') : Promise.resolve(null), this.safe('/cluster/sdn/zones', warnings, 'SDN zones'), this.safe('/cluster/sdn/vnets', warnings, 'SDN VNets'), this.safe('/cluster/sdn/ipams', warnings, 'SDN IPAMs')]); return this.result(tool, { node: node || null, interfaces: network || [], zones: zones || [], vnets: vnets || [], ipams: ipams || [] }, { endpoint: ['/nodes/{node}/network', '/cluster/sdn/zones', '/cluster/sdn/vnets', '/cluster/sdn/ipams'], node, warnings, partial: warnings.length > 0 }); }
  async journal(tool, args) {
    const node = this.validateNode(args);
    const lastentries = parseBoundedInteger(args.lastentries, { name: 'lastentries', defaultValue: 50, min: 1, max: 200 });
    const endpoint = this.endpoint(`/nodes/${node}/journal`, { lastentries, since: args.since, until: args.until, startcursor: args.startcursor, endcursor: args.endcursor });
    const entries = await this.server.proxmoxRequest(endpoint) || [];
    return this.result(tool, { entries, query: { lastentries, since: args.since ?? null, until: args.until ?? null, startcursor: args.startcursor ?? null, endcursor: args.endcursor ?? null }, count: entries.length }, { endpoint, node });
  }
  validateInterface(iface) {
    if (typeof iface !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(iface)) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Invalid interface name.', operation: 'network interface' });
    return iface;
  }
  validateVnet(vnet) {
    if (typeof vnet !== 'string' || !/^[A-Za-z][A-Za-z0-9]*[A-Za-z0-9]$/.test(vnet) || vnet.length < 2 || vnet.length > 8) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', source: 'mcp', message: 'Invalid Proxmox VNet ID. The official backend requires 2-8 alphanumeric characters, starting with a letter.', operation: 'sdn vnet' });
    return vnet;
  }
  validateVnetAlias(alias) {
    if (typeof alias !== 'string' || alias.length > 256 || !/^[()\-_.\w\d\s]{0,256}$/i.test(alias)) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', source: 'mcp', message: 'Invalid VNet alias. The official backend accepts up to 256 letters, digits, whitespace, parentheses, hyphens, underscores, and periods.', operation: 'sdn vnet alias' });
    return alias;
  }
  validateZone(zone) {
    if (typeof zone !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/.test(zone)) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Invalid SDN zone name.', operation: 'sdn zone' });
    return zone;
  }
  validateVlan(tag) { return parseBoundedInteger(tag, { name: 'vlan_tag', min: 1, max: 4094 }); }
  requireWrite(tool) {
    if (!this.server.allowElevated) throw new ProxmoxMcpError({ code: 'PROXMOX_WRITE_NOT_ALLOWED', category: 'authorization', message: `${tool} is a WRITE operation, but elevated writes are disabled. Set PROXMOX_ALLOW_ELEVATED=true; dry-run remains available, and explicit confirmation is still required for execution.`, operation: tool });
  }
  requireConfirmation(tool, args, key = 'confirm') {
    if (args.dry_run !== false) return false;
    if (args[key] !== true) throw new ProxmoxMcpError({ code: 'PROXMOX_EXPLICIT_CONFIRMATION_REQUIRED', category: 'validation', message: `Set dry_run=false and ${key}=true to perform this write.`, operation: tool });
    this.requireWrite(tool); return true;
  }
  normalizeDns(value) {
    return Object.fromEntries(['dns1', 'dns2', 'dns3', 'search'].map((field) => [field, value?.[field] ?? null]));
  }
  validateDnsAddress(value, field) {
    if (typeof value !== 'string' || value.length > 45 || value.trim() !== value || !isIP(value)) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: `${field} must be one valid IPv4 or IPv6 address.`, operation: 'node DNS update' });
    return value;
  }
  validateDnsSearch(value) {
    // The PVE API stores a single search-domain string. Keep it to one DNS
    // name so a caller cannot smuggle arbitrary resolv.conf directives.
    if (typeof value !== 'string' || value.length < 1 || value.length > 253 || value.trim() !== value || !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value)) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'search must be one valid DNS search domain without whitespace.', operation: 'node DNS update' });
    return value;
  }
  buildNodeDnsRequest(node, before, args) {
    const fields = ['dns1', 'dns2', 'dns3', 'search']; const body = {}; const deleted = [];
    for (const field of fields) {
      const clear = args[`clear_${field}`] === true;
      if (clear && args[field] !== undefined) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: `Do not supply ${field} when clear_${field}=true.`, operation: 'node DNS update' });
      if (clear) { deleted.push(field); continue; }
      if (args[field] === undefined) continue;
      body[field] = field === 'search' ? this.validateDnsSearch(args[field]) : this.validateDnsAddress(args[field], field);
    }
    if (!Object.keys(body).length && !deleted.length) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Provide at least one DNS field to set or clear.', operation: 'node DNS update' });
    if (deleted.length) body.delete = deleted;
    const after = { ...before };
    for (const field of deleted) after[field] = null;
    for (const field of fields) if (body[field] !== undefined) after[field] = body[field];
    if (!after.dns1 && !after.dns2 && !after.dns3 && args.allow_empty_dns !== true) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Refusing to leave the node without a DNS server. Supply a DNS address or set allow_empty_dns=true.', operation: 'node DNS update' });
    return { endpoint: `/nodes/${node}/dns`, method: 'PUT', content_type: 'application/json', body, accepted_fields: [...fields, 'delete'], omitted_fields: fields.filter((field) => body[field] === undefined && !deleted.includes(field)), before, after, changed_fields: fields.filter((field) => before[field] !== after[field]) };
  }
  async updateNodeDns(tool, args) {
    const node = this.validateNode(args); const endpoint = `/nodes/${node}/dns`;
    const before = this.normalizeDns(await this.server.proxmoxRequest(endpoint) || {});
    const request = this.buildNodeDnsRequest(node, before, args);
    const plan = { request, before, after: request.after, changed_fields: request.changed_fields, reloadRequired: false, reloadPerformed: false, rebootPerformed: false, file: '/etc/resolv.conf' };
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, ...plan }, { endpoint, node, warnings: [{ code: 'DNS_CHANGE_NOT_APPLIED', message: 'Dry-run only. Node DNS configuration was not changed.' }] });
    await this.executeRequest(request);
    const after = this.normalizeDns(await this.server.proxmoxRequest(endpoint) || {});
    if (JSON.stringify(after) !== JSON.stringify(request.after)) throw new ProxmoxMcpError({ code: 'PROXMOX_POSTCONDITION_FAILED', category: 'api', message: 'Node DNS update did not produce the requested configuration.', operation: request.endpoint, details: { expected: request.after, observed: after } });
    return this.result(tool, { dry_run: false, ...plan, after, postcondition_verified: true }, { endpoint, node });
  }
  async updateNetworkComment(tool, args) {
    const node = this.validateNode(args); const iface = this.validateInterface(args.iface);
    if (args.clear_comment !== true && (typeof args.comment !== 'string' || !args.comment.length || args.comment.length > 2048 || /\u0000/.test(args.comment))) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Provide a non-empty comment up to 2048 characters, or set clear_comment=true.', operation: tool });
    if (args.clear_comment === true && args.comment !== undefined) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Do not supply comment when clear_comment=true.', operation: tool });
    const listEndpoint = `/nodes/${node}/network`; const interfaces = await this.server.proxmoxRequest(listEndpoint) || [];
    const before = interfaces.find((entry) => entry.iface === iface);
    if (!before) throw new ProxmoxMcpError({ code: 'PROXMOX_NOT_FOUND', category: 'not_found', message: `Network interface ${iface} does not exist on node ${node}.`, operation: listEndpoint });
    const request = this.buildNetworkCommentRequest(node, iface, before, args);
    const plan = this.networkCommentPlan(before, request);
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, ...plan }, { endpoint: [listEndpoint, request.endpoint], node, warnings: [{ code: 'NETWORK_CHANGE_NOT_APPLIED', message: 'Dry-run only. Proxmox network configuration was not changed.' }] });
    await this.executeRequest(request);
    const afterInterfaces = await this.server.proxmoxRequest(listEndpoint) || [];
    const after = afterInterfaces.find((entry) => entry.iface === iface);
    if (!after) throw new ProxmoxMcpError({ code: 'PROXMOX_POSTCONDITION_FAILED', category: 'api', message: `Network interface ${iface} was not returned after the comment update.`, operation: request.endpoint });
    const changedFields = this.networkChangedFields(before, after);
    const expectedComment = request.body.comments ?? '';
    if (!this.sameComment(after.comments ?? '', expectedComment) || changedFields.some((field) => field !== 'comments')) throw new ProxmoxMcpError({ code: 'PROXMOX_POSTCONDITION_FAILED', category: 'api', message: 'Network comment update did not preserve unrelated interface fields.', operation: request.endpoint, details: { changedFields } });
    return this.result(tool, { dry_run: false, ...this.networkCommentPlan(before, request, after), postcondition_verified: true }, { endpoint: [listEndpoint, request.endpoint], node, warnings: [{ code: 'NETWORK_CHANGE_PENDING', message: 'The comment change is staged. No network reload or node restart was performed.' }] });
  }
  buildNetworkCommentRequest(node, iface, before, args) {
    // PVE's PUT /nodes/{node}/network/{iface} schema requires iface and type.
    // PUT accepts a different schema from GET. Carry forward only fields
    // accepted by the network update schema; method/families/active and
    // bridge_stp/bridge_fd are response fields and must not be echoed.
    const preserved = ['address', 'netmask', 'gateway', 'gateway6', 'autostart', 'bridge_ports', 'bridge_vlan_aware', 'bridge_vids', 'mtu', 'bond_mode', 'bond_primary', 'bond_slaves', 'ovs_bonds', 'ovs_bridge', 'ovs_options', 'ovs_type', 'options', 'vlan_id', 'vlan_raw_device'];
    const body = { iface, type: before.type };
    for (const field of preserved) {
      if (before[field] === undefined || before[field] === null) continue;
      body[field] = field === 'netmask' ? this.networkNetmask(before) : before[field];
    }
    if (args.clear_comment === true) body.delete = ['comments']; else body.comments = args.comment;
    return { endpoint: `/nodes/${node}/network/${encodeURIComponent(iface)}`, method: 'PUT', content_type: 'application/json', body, accepted_fields: ['iface', 'type', ...preserved, 'comments', 'delete'], omitted_fields: Object.keys(before).filter((key) => !['iface', 'type', 'comments', 'digest', ...preserved].includes(key)).sort() };
  }
  networkNetmask(before) {
    const value = String(before.netmask ?? '');
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return value;
    const bits = Number(String(before.cidr || '').split('/')[1] || value);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Cannot derive a valid IPv4 netmask from the current network interface configuration.', operation: 'network update' });
    return [0, 8, 16, 24].map((shift) => {
      const octetBits = Math.max(0, Math.min(8, bits - shift));
      return octetBits === 0 ? 0 : 256 - 2 ** (8 - octetBits);
    }).join('.');
  }
  executeRequest(request) { return this.server.proxmoxRequest(request.endpoint, request.method, request.body); }
  sameComment(actual, expected) { return String(actual).replace(/\n$/, '') === String(expected).replace(/\n$/, ''); }
  networkChangedFields(before, after) {
    const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
    return [...keys].filter((key) => JSON.stringify(before[key] ?? null) !== JSON.stringify(after[key] ?? null));
  }
  networkCommentPlan(before, request, after = null) {
    const proposed = request.body.comments ?? '';
    return { request, before: { iface: before.iface, comments: before.comments ?? '' }, after: { iface: before.iface, comments: after?.comments ?? proposed }, changed_fields: ['comments'], pending: true, reloadRequired: true, reloadPerformed: false, rebootPerformed: false };
  }
  networkOptions(value) {
    if (value === undefined || value === null || value === '') return [];
    const items = Array.isArray(value) ? value : [value];
    return items.flatMap((item) => String(item).split('\n')).map((item) => item.trim()).filter(Boolean);
  }
  bridgeMcsnoopOptions(before, enabled) {
    const retained = this.networkOptions(before.options).filter((line) => !/^bridge-mcsnoop(?:\s|$)/.test(line));
    retained.push(`bridge-mcsnoop ${enabled ? '1' : '0'}`);
    return retained;
  }
  async setBridgeMulticastSnooping(tool, args) {
    const node = this.validateNode(args); const iface = this.validateInterface(args.iface);
    if (typeof args.enabled !== 'boolean') throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'enabled must be a boolean.', operation: tool });
    if (args.apply_network === true && args.confirm_network_reload !== true && args.dry_run === false) throw new ProxmoxMcpError({ code: 'PROXMOX_EXPLICIT_CONFIRMATION_REQUIRED', category: 'validation', message: 'Set confirm_network_reload=true when apply_network=true.', operation: tool });
    const listEndpoint = `/nodes/${node}/network`; const interfaces = await this.server.proxmoxRequest(listEndpoint) || [];
    const before = interfaces.find((entry) => entry.iface === iface);
    if (!before) throw new ProxmoxMcpError({ code: 'PROXMOX_NOT_FOUND', category: 'not_found', message: `Network interface ${iface} does not exist on node ${node}.`, operation: listEndpoint });
    if (before.type !== 'bridge') throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: `${iface} on ${node} is not a bridge.`, operation: tool });
    const options = this.bridgeMcsnoopOptions(before, args.enabled);
    const request = this.buildNetworkUpdateRequest(node, iface, before, { options });
    const plan = { request, before: { iface, type: before.type, options: this.networkOptions(before.options) }, after: { iface, type: before.type, options }, changed_fields: ['options'], pending: true, reloadRequired: true, reloadPerformed: false, rebootPerformed: false };
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, ...plan }, { endpoint: [listEndpoint, request.endpoint], node, warnings: [{ code: 'NETWORK_CHANGE_NOT_APPLIED', message: 'Dry-run only. Bridge multicast-snooping configuration was not changed.' }] });
    await this.executeRequest(request);
    if (args.apply_network === true) await this.server.proxmoxRequest(`/nodes/${node}/network`, 'PUT', {});
    const afterInterfaces = await this.server.proxmoxRequest(listEndpoint) || [];
    const after = afterInterfaces.find((entry) => entry.iface === iface);
    if (!after || !this.networkOptions(after.options).includes(`bridge-mcsnoop ${args.enabled ? '1' : '0'}`)) throw new ProxmoxMcpError({ code: 'PROXMOX_POSTCONDITION_FAILED', category: 'api', message: 'Bridge multicast-snooping update was not observed after the Proxmox API request.', operation: request.endpoint, details: { expected: `bridge-mcsnoop ${args.enabled ? '1' : '0'}`, observed: after?.options ?? null } });
    return this.result(tool, { dry_run: false, ...plan, after: { iface, type: after.type, options: this.networkOptions(after.options) }, pending: args.apply_network !== true, reloadPerformed: args.apply_network === true, postcondition_verified: true }, { endpoint: args.apply_network === true ? [request.endpoint, `/nodes/${node}/network`] : request.endpoint, node, warnings: args.apply_network === true ? [] : [{ code: 'NETWORK_CHANGE_PENDING', message: 'Bridge configuration is staged. No network reload was performed.' }] });
  }
  buildNetworkUpdateRequest(node, iface, before, updates) {
    const base = this.buildNetworkCommentRequest(node, iface, before, { clear_comment: true });
    delete base.body.delete;
    if (before.comments !== undefined && before.comments !== null) base.body.comments = before.comments;
    Object.assign(base.body, updates);
    return base;
  }
  async vnetState(tool, args) {
    const vnet = args.vnet === undefined ? null : this.validateVnet(args.vnet);
    const [pending, running] = await Promise.all([this.server.proxmoxRequest('/cluster/sdn/vnets?pending=1') || [], this.server.proxmoxRequest('/cluster/sdn/vnets?running=1') || []]);
    const select = (items) => vnet ? items.filter((item) => item.vnet === vnet) : items;
    const selectedPending = select(pending); const selectedRunning = select(running);
    return this.result(tool, { vnet, pending: selectedPending, running: selectedRunning, pending_identity: this.vnetIdentity(selectedPending), running_identity: this.vnetIdentity(selectedRunning), has_pending_changes: this.stableJson(selectedPending) !== this.stableJson(selectedRunning) }, { endpoint: ['/cluster/sdn/vnets?pending=1', '/cluster/sdn/vnets?running=1'] });
  }
  stableJson(value) {
    if (Array.isArray(value)) return `[${value.map((item) => this.stableJson(item)).sort().join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${this.stableJson(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
  }
  vnetIdentity(vnets) {
    return (Array.isArray(vnets) ? vnets : []).map((entry) => ({ id: entry.vnet, alias: entry.alias ?? null, description: null, display_name: entry.alias || entry.vnet }));
  }
  vnetBody(args, { requireZone = false } = {}) {
    const body = {};
    if (requireZone || args.zone !== undefined) body.zone = this.validateZone(args.zone);
    if (args.vlan_tag !== undefined) body.tag = this.validateVlan(args.vlan_tag);
    if (args.alias !== undefined) body.alias = this.validateVnetAlias(args.alias);
    if (args.vlan_aware !== undefined) body.vlanaware = args.vlan_aware ? 1 : 0;
    if (args.isolate_ports !== undefined) body['isolate-ports'] = args.isolate_ports ? 1 : 0;
    return body;
  }
  async getVnet(vnet) {
    const data = await this.server.proxmoxRequest('/cluster/sdn/vnets'); const vnetConfig = (Array.isArray(data) ? data : []).find((entry) => entry.vnet === vnet);
    if (!vnetConfig) throw new ProxmoxMcpError({ code: 'PROXMOX_NOT_FOUND', category: 'not_found', message: `SDN VNet ${vnet} does not exist.`, statusCode: 404, operation: '/cluster/sdn/vnets' });
    return vnetConfig;
  }
  async ensureZone(zone) {
    const data = await this.server.proxmoxRequest('/cluster/sdn/zones'); const zones = Array.isArray(data) ? data : [];
    if (!zones.some((entry) => entry.zone === zone)) throw new ProxmoxMcpError({ code: 'PROXMOX_NOT_FOUND', category: 'not_found', message: `SDN zone ${zone} does not exist.`, statusCode: 404, operation: '/cluster/sdn/zones' });
  }
  async createVnet(tool, args) {
    const vnet = this.validateVnet(args.vnet); const body = { vnet, type: 'vnet', ...this.vnetBody(args, { requireZone: true }) };
    const existingData = await this.server.proxmoxRequest('/cluster/sdn/vnets'); const existing = (Array.isArray(existingData) ? existingData : []).find((entry) => entry.vnet === vnet);
    if (existing) throw new ProxmoxMcpError({ code: 'PROXMOX_CONFLICT', category: 'conflict', message: `SDN VNet ${vnet} already exists.`, operation: tool });
    await this.ensureZone(body.zone);
    const request = this.buildVnetRequest('create', vnet, body);
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, action: 'create', request, before: null, after: body, pending: true, applyRequired: true }, { endpoint: ['/cluster/sdn/vnets/{vnet}', '/cluster/sdn/zones/{zone}', request.endpoint] });
    await this.executeRequest(request);
    return this.result(tool, { dry_run: false, action: 'create', request, before: null, after: body, pending: true, applyRequired: true }, { endpoint: request.endpoint, warnings: [{ code: 'SDN_CHANGE_PENDING', message: 'VNet configuration is pending. Use the separately confirmed apply tool when ready.' }] });
  }
  async updateVnet(tool, args) {
    const vnet = this.validateVnet(args.vnet); const before = await this.getVnet(vnet); const body = this.vnetBody(args);
    if (!Object.keys(body).length) throw new ProxmoxMcpError({ code: 'PROXMOX_VALIDATION_ERROR', category: 'validation', message: 'Provide at least one mutable VNet field.', operation: tool });
    if (body.zone !== undefined) await this.ensureZone(body.zone);
    const request = this.buildVnetRequest('update', vnet, body);
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, action: 'update', request, before, after: { ...before, ...body }, pending: true, applyRequired: true }, { endpoint: request.endpoint });
    await this.executeRequest(request);
    return this.result(tool, { dry_run: false, action: 'update', request, before, after: { ...before, ...body }, pending: true, applyRequired: true }, { endpoint: request.endpoint, warnings: [{ code: 'SDN_CHANGE_PENDING', message: 'VNet configuration is pending; no SDN apply was run.' }] });
  }
  async vnetReferences(vnet) {
    const guests = await this.server.proxmoxRequest('/cluster/resources?type=vm') || []; const escaped = vnet.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); const bridge = new RegExp(`(?:^|,)bridge=${escaped}(?:,|$)`);
    const references = [];
    for (const guest of guests.filter((item) => ['qemu', 'lxc'].includes(item.type) && item.node && item.vmid)) {
      const config = await this.server.proxmoxRequest(`/nodes/${this.server.validateNodeName(guest.node)}/${guest.type}/${this.server.validateVMID(guest.vmid)}/config`) || {};
      if (Object.entries(config).some(([key, value]) => /^net\d+$/.test(key) && bridge.test(String(value)))) references.push({ vmid: guest.vmid, type: guest.type, node: guest.node });
    }
    return references;
  }
  async deleteVnet(tool, args) {
    const vnet = this.validateVnet(args.vnet); const before = await this.getVnet(vnet); const references = await this.vnetReferences(vnet);
    if (references.length) throw new ProxmoxMcpError({ code: 'PROXMOX_CONFLICT', category: 'conflict', message: `SDN VNet ${vnet} is referenced by guests and cannot be deleted.`, operation: tool, details: { references } });
    const request = this.buildVnetRequest('delete', vnet);
    if (!this.requireConfirmation(tool, args)) return this.result(tool, { dry_run: true, action: 'delete', request, before, references, pending: true, applyRequired: true }, { endpoint: request.endpoint });
    await this.executeRequest(request);
    return this.result(tool, { dry_run: false, action: 'delete', request, before, references, pending: true, applyRequired: true }, { endpoint: request.endpoint, warnings: [{ code: 'SDN_CHANGE_PENDING', message: 'VNet deletion is pending; no SDN apply was run.' }] });
  }
  async applySdn(tool, args) {
    const state = await this.vnetState(tool, {}); const data = state.structuredContent;
    const request = { endpoint: '/cluster/sdn', method: 'PUT', content_type: 'application/json', body: {}, accepted_fields: [], omitted_fields: [] };
    const consequence = 'Applying SDN applies all pending changes and invokes Proxmox network reload.';
    if (args.dry_run !== false) return this.result(tool, { dry_run: true, request, pending: data.pending, running: data.running, consequence, requiredAcknowledgements: ['confirm_apply_all_pending', 'confirm_network_reload'] }, { endpoint: ['/cluster/sdn/vnets?pending=1', '/cluster/sdn/vnets?running=1', request.endpoint] });
    this.requireConfirmation(tool, args, 'confirm_apply_all_pending');
    this.requireConfirmation(tool, args, 'confirm_network_reload');
    const result = await this.executeRequest(request);
    return this.result(tool, { dry_run: false, request, applied: true, result, consequence }, { endpoint: request.endpoint });
  }
  buildVnetRequest(action, vnet, body = undefined) {
    if (action === 'create') return { endpoint: '/cluster/sdn/vnets', method: 'POST', content_type: 'application/json', body, accepted_fields: ['vnet', 'type', 'zone', 'tag', 'alias', 'vlanaware', 'isolate-ports'], omitted_fields: [] };
    const endpoint = `/cluster/sdn/vnets/${encodeURIComponent(vnet)}`;
    if (action === 'update') return { endpoint, method: 'PUT', content_type: 'application/json', body, accepted_fields: ['zone', 'tag', 'alias', 'vlanaware', 'isolate-ports'], omitted_fields: [] };
    return { endpoint, method: 'DELETE', content_type: null, body: null, accepted_fields: [], omitted_fields: [] };
  }
  async cephStatus(tool) { try { const status = await this.server.proxmoxRequest('/cluster/ceph/status'); return this.result(tool, { configured: true, status }, { endpoint: '/cluster/ceph/status' }); } catch (error) { const typed = errorFromUnknown(error, '/cluster/ceph/status'); if (typed.statusCode === 404 || typed.statusCode === 500) return this.unavailable(tool, 'CEPH_NOT_CONFIGURED_OR_UNAVAILABLE', 'Ceph is not configured or is unavailable through this Proxmox API endpoint.', '/cluster/ceph/status'); throw error; } }
}
