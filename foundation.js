/**
 * Cross-cutting safety primitives for the Proxmox MCP.  This module is kept
 * dependency-free so the transport and tool layers share the same policy.
 */

export const TOOL_CLASSIFICATIONS = Object.freeze({
  proxmox_get_nodes: 'READ', proxmox_get_node_status: 'READ',
  proxmox_get_vms: 'READ', proxmox_get_vm_status: 'READ',
  proxmox_get_storage: 'READ', proxmox_get_cluster_status: 'READ',
  proxmox_list_templates: 'READ', proxmox_get_next_vmid: 'READ',
  proxmox_list_snapshots_lxc: 'READ', proxmox_list_snapshots_vm: 'READ',
  proxmox_list_backups: 'READ', proxmox_generate_terraform: 'READ',
  proxmox_get_task_status: 'READ', proxmox_get_vm_config: 'READ',
  proxmox_whoami: 'READ', proxmox_get_guest_ips: 'READ',
  proxmox_get_rrd_data: 'READ', proxmox_get_pools: 'READ',
  proxmox_get_ha_resources: 'READ', proxmox_get_firewall_rules: 'READ',
  proxmox_execute_vm_command: 'WRITE',
  proxmox_create_lxc: 'WRITE', proxmox_create_vm: 'WRITE',
  proxmox_start_lxc: 'WRITE', proxmox_start_vm: 'WRITE',
  proxmox_stop_lxc: 'WRITE', proxmox_stop_vm: 'WRITE',
  proxmox_delete_lxc: 'WRITE', proxmox_delete_vm: 'WRITE',
  proxmox_reboot_lxc: 'WRITE', proxmox_reboot_vm: 'WRITE',
  proxmox_shutdown_lxc: 'WRITE', proxmox_shutdown_vm: 'WRITE',
  proxmox_pause_vm: 'WRITE', proxmox_resume_vm: 'WRITE',
  proxmox_clone_lxc: 'WRITE', proxmox_clone_vm: 'WRITE',
  proxmox_resize_lxc: 'WRITE', proxmox_resize_vm: 'WRITE',
  proxmox_create_snapshot_lxc: 'WRITE', proxmox_create_snapshot_vm: 'WRITE',
  proxmox_rollback_snapshot_lxc: 'WRITE', proxmox_rollback_snapshot_vm: 'WRITE',
  proxmox_delete_snapshot_lxc: 'WRITE', proxmox_delete_snapshot_vm: 'WRITE',
  proxmox_create_backup_lxc: 'WRITE', proxmox_create_backup_vm: 'WRITE',
  proxmox_restore_backup_lxc: 'WRITE', proxmox_restore_backup_vm: 'WRITE',
  proxmox_delete_backup: 'WRITE', proxmox_add_disk_vm: 'WRITE',
  proxmox_add_mountpoint_lxc: 'WRITE', proxmox_resize_disk_vm: 'WRITE',
  proxmox_resize_disk_lxc: 'WRITE', proxmox_remove_disk_vm: 'WRITE',
  proxmox_remove_mountpoint_lxc: 'WRITE', proxmox_move_disk_vm: 'WRITE',
  proxmox_move_disk_lxc: 'WRITE', proxmox_add_network_vm: 'WRITE',
  proxmox_add_network_lxc: 'WRITE', proxmox_update_network_vm: 'WRITE',
  proxmox_update_network_lxc: 'WRITE', proxmox_remove_network_vm: 'WRITE',
  proxmox_remove_network_lxc: 'WRITE', proxmox_migrate_vm: 'WRITE',
  proxmox_convert_to_template: 'WRITE', proxmox_set_cloudinit: 'WRITE',
  proxmox_list_tasks: 'READ', proxmox_audit_task_failures: 'READ', proxmox_get_task_log: 'READ',
  proxmox_list_backup_jobs: 'READ', proxmox_audit_backup_coverage: 'READ',
  proxmox_audit_cluster_state: 'READ', proxmox_list_ha_groups: 'READ', proxmox_get_ha_status: 'READ', proxmox_list_replication_jobs: 'READ',
  proxmox_list_node_repositories: 'READ', proxmox_list_node_packages: 'READ', proxmox_get_node_version: 'READ', proxmox_get_node_subscription: 'READ', proxmox_list_node_certificates: 'READ', proxmox_audit_certificate_expiry: 'READ', proxmox_get_node_report: 'READ', proxmox_get_node_dns: 'READ',
  proxmox_list_access_control: 'READ', proxmox_audit_access_control: 'READ', proxmox_list_node_disks: 'READ', proxmox_get_disk_smart: 'READ', proxmox_list_zfs_pools: 'READ', proxmox_list_lvm: 'READ', proxmox_list_lvmthin: 'READ', proxmox_audit_storage_health: 'READ',
  proxmox_list_node_network: 'READ', proxmox_list_sdn_zones: 'READ', proxmox_list_sdn_vnets: 'READ', proxmox_list_sdn_ipams: 'READ', proxmox_audit_network_state: 'READ', proxmox_get_node_journal: 'READ', proxmox_list_node_services: 'READ', proxmox_get_ceph_status: 'READ',
  proxmox_get_sdn_vnet_state: 'READ',
  proxmox_update_node_network_comment: 'WRITE', proxmox_set_bridge_multicast_snooping: 'WRITE', proxmox_update_node_dns: 'WRITE', proxmox_create_sdn_vnet: 'WRITE', proxmox_update_sdn_vnet: 'WRITE', proxmox_delete_sdn_vnet: 'WRITE', proxmox_apply_sdn_configuration: 'WRITE',
});

export function getToolClassification(tool) {
  return TOOL_CLASSIFICATIONS[tool] || 'WRITE';
}

export class ProxmoxMcpError extends Error {
  constructor({ code, category, message, retryable = false, statusCode, source = 'proxmox-api', operation, details = {}, cause }) {
    super(redactSensitive(message));
    this.name = 'ProxmoxMcpError';
    this.code = code;
    this.category = category;
    this.retryable = retryable;
    this.statusCode = statusCode;
    this.source = source;
    this.operation = operation;
    this.details = sanitizeDetails(details);
    this.cause = cause;
  }

  toJSON() {
    return {
      code: this.code,
      category: this.category,
      message: this.message,
      retryable: this.retryable,
      ...(this.statusCode !== undefined ? { statusCode: this.statusCode } : {}),
      source: this.source,
      ...(this.operation ? { operation: this.operation } : {}),
      details: this.details,
    };
  }
}

const SECRET_KEY_PATTERN = /(token|secret|password|authorization|cookie|ticket|private.?key|csrf)/i;

export function redactSensitive(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(/(PVEAPIToken=)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/((?:token|secret|password|authorization|cookie|ticket)=[^&\s,;]+)/gi, (match) => {
      const index = match.indexOf('=');
      return `${match.slice(0, index + 1)}[REDACTED]`;
    });
}

export function sanitizeDetails(value) {
  if (Array.isArray(value)) return value.map(sanitizeDetails);
  if (!value || typeof value !== 'object') return typeof value === 'string' ? redactSensitive(value) : value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    SECRET_KEY_PATTERN.test(key) ? '[REDACTED]' : sanitizeDetails(item),
  ]));
}

export function errorFromUnknown(error, operation) {
  if (error instanceof ProxmoxMcpError) return error;
  const message = redactSensitive(error?.message || String(error));
  if (Number.isInteger(error?.statusCode)) {
    return errorForHttpStatus(error.statusCode, message, operation);
  }
  if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
    return new ProxmoxMcpError({ code: 'PROXMOX_REQUEST_TIMEOUT', category: 'timeout', message: 'The Proxmox API request exceeded its deadline.', retryable: true, operation, cause: error });
  }
  if (['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET', 'EHOSTUNREACH', 'EAI_AGAIN'].includes(error?.code) || error?.name === 'FetchError' || /fetch failed/i.test(message)) {
    return new ProxmoxMcpError({ code: 'PROXMOX_NETWORK_ERROR', category: 'network', message: `Failed to connect to Proxmox: ${message}`, retryable: true, operation, details: { networkCode: error?.code }, cause: error });
  }
  if (/self[- ]signed|unable to verify|certificate|tls/i.test(message)) {
    return new ProxmoxMcpError({ code: 'PROXMOX_TLS_ERROR', category: 'tls', message: 'TLS certificate verification failed for the Proxmox API.', retryable: false, operation, cause: error });
  }
  return new ProxmoxMcpError({ code: 'MCP_INTERNAL_ERROR', category: 'internal', message, retryable: false, source: 'mcp', operation, cause: error });
}

export function errorForHttpStatus(statusCode, message, operation) {
  const safeMessage = redactSensitive(message || `Proxmox API returned HTTP ${statusCode}.`);
  if (statusCode === 401) return new ProxmoxMcpError({ code: 'PROXMOX_AUTHENTICATION_FAILED', category: 'authentication', message: safeMessage, statusCode, operation });
  if (statusCode === 403) return new ProxmoxMcpError({ code: 'PROXMOX_PERMISSION_DENIED', category: 'authorization', message: safeMessage, statusCode, operation });
  if (statusCode === 404) return new ProxmoxMcpError({ code: 'PROXMOX_NOT_FOUND', category: 'not_found', message: safeMessage, statusCode, operation });
  if (statusCode === 409) return new ProxmoxMcpError({ code: 'PROXMOX_CONFLICT', category: 'conflict', message: safeMessage, statusCode, operation });
  return new ProxmoxMcpError({ code: 'PROXMOX_API_ERROR', category: 'api', message: safeMessage, retryable: isRetryableHttpStatus(statusCode), statusCode, operation });
}

export function isRetryableHttpStatus(status) {
  return status === 429 || status === 502 || status === 503 || status === 504;
}

export function shouldRetry({ method, error }) {
  return method === 'GET' && error instanceof ProxmoxMcpError && error.retryable;
}

export function retryDelayMs(attempt, retryAfterMs = null, random = Math.random) {
  if (Number.isFinite(retryAfterMs) && retryAfterMs >= 0) return Math.min(retryAfterMs, 5000);
  const capped = Math.min(250 * (2 ** attempt), 5000);
  return Math.min(Math.floor(capped * (0.5 + random())), 5000);
}

export function parseBoundedInteger(value, { name, defaultValue, min, max }) {
  if (value === undefined || value === null || value === '') return defaultValue;
  if (!/^[0-9]+$/.test(String(value))) throw new Error(`${name} must be an integer between ${min} and ${max}`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name} must be an integer between ${min} and ${max}`);
  return parsed;
}

export class RequestLimiter {
  constructor(limit) {
    this.limit = limit;
    this.active = 0;
    this.queue = [];
  }

  async run(operation) {
    await new Promise((resolve) => {
      const start = () => { this.active += 1; resolve(); };
      if (this.active < this.limit) start(); else this.queue.push(start);
    });
    try { return await operation(); } finally {
      this.active -= 1;
      this.queue.shift()?.();
    }
  }
}

export function makeAuditEnvelope({ ok, tool, classification, data, error, source, warnings = [], partial = false }) {
  return {
    ok,
    tool,
    classification,
    timestamp: new Date().toISOString(),
    ...(source ? { source } : {}),
    ...(ok ? { data: data ?? {} } : { error: error instanceof ProxmoxMcpError ? error.toJSON() : sanitizeDetails(error) }),
    warnings: sanitizeDetails(warnings),
    evidence: { retrievalMethod: source?.type === 'proxmox-api' ? 'REST' : 'unknown', confidence: source ? 'high' : 'unknown', partial },
  };
}
