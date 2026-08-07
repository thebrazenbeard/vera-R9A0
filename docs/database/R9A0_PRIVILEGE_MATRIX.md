# R9A0 Privilege Matrix

| Surface | `anon` | `authenticated` | `service_role` | `r9a0_owner` | `postgres` |
|---|---:|---:|---:|---:|---:|
| R9A0 schemas | none | none | usage | owner | admin |
| Coordination base table | none | none | select through an explicit RLS policy | owner policy | admin |
| Coordination views | none | none | select through the base-table RLS policy | owner | admin |
| Migration receipts | none | none | select through an explicit RLS policy | owner policy | admin |
| `append_coordination_event` | none | none | execute | owner | admin |
| Direct coordination insert | none | none | none | only through owned function or controlled SQL | admin |
| Update/delete/truncate append-only rows | blocked | blocked | blocked | blocked by trigger | blocked by trigger |
| Login capability | n/a | n/a | platform role | **NOLOGIN** | login/admin |
| RLS bypass | no | no | platform-defined | **no** | admin |

`r9a0_owner` is the least-privilege ownership boundary for R9A0 schemas, tables, views, sequences, and privileged functions. RLS is forced on the append-only base tables. The service role has no direct mutation privileges and writes only through the narrow security-definer RPC. Its read access is intentionally limited to named `SELECT` policies on the two governed base tables; the security-invoker views inherit that RLS boundary.
