# Proxmox SDN VNet identifier contract

This MCP distinguishes the technical Proxmox VNet identifier from its
human-readable alias.

| Field | Proxmox API field | Contract | MCP behavior |
| --- | --- | --- | --- |
| Technical identifier | `vnet` | 2–8 ASCII alphanumeric characters; starts with a letter | Required for create, update, delete, and state filters; never rewritten by update. |
| Human-readable alias | `alias` | Optional; up to 256 characters matching Proxmox's alias character pattern (letters, digits, whitespace, parentheses, hyphens, underscores, and periods) | Exposed by SDN reads and independently mutable by create/update. |
| Description | — | Not supported for VNets by the Proxmox API schema | Reported as `null`; never serialized. |
| Display name | — | Not a separate API field | MCP reports `alias` when present, otherwise the technical ID. |

The Proxmox backend rule is implemented by the `pve-sdn-vnet-id` schema in
`PVE::Network::SDN::VnetPlugin`: its pattern is
`[a-zA-Z][a-zA-Z0-9]*[a-zA-Z0-9]`, with `minLength => 2` and `maxLength => 8`.
The MCP validates the same rule before a write is planned. A rejected
preflight is an MCP validation result, not an HTTP response from Proxmox.

`proxmox_list_sdn_vnets` returns both the native `vnets` records and the
explicit `vnet_identity` view. `proxmox_get_sdn_vnet_state` returns the same
view for both `pending` and `running` state. The view has `id`, `alias`,
`description`, and `display_name` fields so callers cannot confuse them.
Pending state is compared semantically (including stable object-key ordering),
so a REST serialization-order difference is never reported as a configuration
change.

Dry-run and confirmed VNet writes use the same canonical request builder.
Updating `alias` sends only `alias` to `PUT /cluster/sdn/vnets/{vnet}`; it
cannot rename the VNet ID.

Official references:

- https://lore.proxmox.com/pve-devel/20260611145935.147788-6-d.riley%40proxmox.com/
- https://lore.proxmox.com/pve-devel/20250228140136.124286-5-s.hanreich%40proxmox.com/
