# R9A0 Privilege Matrix

| Surface | `anon` | `authenticated` | `service_role` | `postgres` |
|---|---:|---:|---:|---:|
| `r9a0_governance` schema | none | none | usage | owner/admin |
| `r9a0_coordination` schema | none | none | usage | owner/admin |
| `r9a0_api` schema | none | none | usage | owner/admin |
| Coordination base table | none | none | select | owner/admin |
| Coordination views | none | none | select | owner/admin |
| Migration receipts | none | none | select | owner/admin |
| `append_coordination_event` | none | none | execute | owner/admin |
| Direct coordination insert | none | none | none | owner/admin |
| Update/delete/truncate append-only rows | blocked | blocked | blocked | blocked by trigger |

`service_role` bypassing RLS does not confer SQL privileges that were revoked. The write path remains the narrow security-definer RPC.
