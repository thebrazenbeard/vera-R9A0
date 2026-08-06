#!/usr/bin/env bash
set -euo pipefail

: "${R9A0_TEST_DATABASE_URL:?Set R9A0_TEST_DATABASE_URL to a disposable PostgreSQL database.}"

if [[ "${R9A0_DISPOSABLE_DATABASE_CONFIRMED:-}" != "YES" ]]; then
  echo "Refusing to run: set R9A0_DISPOSABLE_DATABASE_CONFIRMED=YES for a disposable database." >&2
  exit 2
fi

case "$R9A0_TEST_DATABASE_URL" in
  *klmbpaigzeguvnpccqzz*|*agvhmutlrolbaijzlbqk*|*qhccsoisgyjzlchievhk*)
    echo "Refusing to run against a known hosted Vera, BT2, or former R9A0 project." >&2
    exit 2
    ;;
esac

command -v psql >/dev/null 2>&1 || {
  echo "psql is required." >&2
  exit 2
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

suffix="$(date -u +%Y%m%d%H%M%S)-$$"
psql_base=(psql "$R9A0_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1)

function_exists="$("${psql_base[@]}" <<'SQL'
select to_regprocedure(
  'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)'
) is not null;
SQL
)"
if [[ "$(printf '%s\n' "$function_exists" | tail -n 1)" != "t" ]]; then
  echo "Required R9A0 append function is not installed." >&2
  exit 2
fi

wait_for_file() {
  local path="$1"
  local label="$2"

  for _ in {1..200}; do
    [[ -f "$path" ]] && return 0
    sleep 0.05
  done

  echo "Timed out waiting for $label." >&2
  return 1
}

wait_for_advisory_waiter() {
  local application_name="$1"
  local label="$2"
  local waiter_count

  for _ in {1..200}; do
    waiter_count="$("${psql_base[@]}" -v app_name="$application_name" <<'SQL'
select count(*)
from pg_catalog.pg_stat_activity a
join pg_catalog.pg_locks l on l.pid = a.pid
where a.application_name = :'app_name'
  and l.locktype = 'advisory'
  and not l.granted;
SQL
)"
    waiter_count="$(printf '%s\n' "$waiter_count" | tail -n 1)"
    if [[ "$waiter_count" =~ ^[0-9]+$ ]] && (( waiter_count >= 1 )); then
      return 0
    fi
    sleep 0.05
  done

  echo "Timed out waiting for $label to block on the R9A0 advisory lock." >&2
  return 1
}

fork_thread="r9a0/test/two-session-fork-${suffix}"
fork_seed_op="r9a0-concurrency-seed-${suffix}"
fork_holder_op="r9a0-concurrency-holder-${suffix}"
fork_waiter_op="r9a0-concurrency-waiter-${suffix}"
fork_holder_app="r9a0-fork-holder-${suffix}"
fork_waiter_app="r9a0-fork-waiter-${suffix}"
fork_ready_file="$tmp_dir/fork-holder-ready"
fork_release_file="$tmp_dir/fork-holder-release"

seed_id="$("${psql_base[@]}" <<SQL
select set_config('request.jwt.claim.role', 'service_role', false);
select (
  r9a0_api.append_coordination_event(
    '${fork_seed_op}',
    '${fork_thread}',
    'test/session-seed',
    'test/concurrency-review',
    'STATUS',
    'IN_PROGRESS',
    'Create the committed predecessor for the deterministic two-session fork test.',
    'Synthetic row in an explicitly disposable test database.',
    null,
    null,
    null,
    '{"synthetic":true,"test":"two-session-fork"}'::jsonb,
    '{"disposable_database_required":true}'::jsonb
  )
)->>'event_id';
SQL
)"
seed_id="$(printf '%s\n' "$seed_id" | tail -n 1)"

run_fork_holder() {
  PGAPPNAME="$fork_holder_app" "${psql_base[@]}" <<SQL
\set VERBOSITY verbose
select set_config('request.jwt.claim.role', 'service_role', false);
begin;
select pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('r9a0-thread:${fork_thread}', 0)
);
\! touch '$fork_ready_file'
\! while [ ! -f '$fork_release_file' ]; do sleep 0.05; done
select (
  r9a0_api.append_coordination_event(
    '${fork_holder_op}',
    '${fork_thread}',
    'test/session-holder',
    'test/concurrency-review',
    'STATUS',
    'IN_PROGRESS',
    'Advance the predecessor while the second session is blocked on the same thread lock.',
    'The holder session proves deterministic overlap before it commits.',
    null,
    '${seed_id}'::uuid,
    null,
    '{"synthetic":true,"test":"two-session-fork"}'::jsonb,
    '{"disposable_database_required":true,"barrier":"advisory-lock"}'::jsonb
  )
)->>'event_id';
commit;
SQL
}

run_fork_waiter() {
  PGAPPNAME="$fork_waiter_app" "${psql_base[@]}" <<SQL
\set VERBOSITY verbose
select set_config('request.jwt.claim.role', 'service_role', false);
begin;
select r9a0_api.append_coordination_event(
  '${fork_waiter_op}',
  '${fork_thread}',
  'test/session-waiter',
  'test/concurrency-review',
  'STATUS',
  'IN_PROGRESS',
  'Attempt the same predecessor while the holder owns the thread lock.',
  'This session must block, then fail after the holder advances the chain.',
  null,
  '${seed_id}'::uuid,
  null,
  '{"synthetic":true,"test":"two-session-fork"}'::jsonb,
  '{"disposable_database_required":true,"barrier":"advisory-lock"}'::jsonb
);
commit;
SQL
}

run_fork_holder >"$tmp_dir/fork-holder.out" 2>"$tmp_dir/fork-holder.err" &
fork_holder_pid=$!
wait_for_file "$fork_ready_file" "fork holder lock acquisition"

run_fork_waiter >"$tmp_dir/fork-waiter.out" 2>"$tmp_dir/fork-waiter.err" &
fork_waiter_pid=$!
wait_for_advisory_waiter "$fork_waiter_app" "fork waiter"
touch "$fork_release_file"

set +e
wait "$fork_holder_pid"
fork_holder_rc=$?
wait "$fork_waiter_pid"
fork_waiter_rc=$?
set -e

if [[ "$fork_holder_rc" -ne 0 || "$fork_waiter_rc" -eq 0 ]]; then
  echo "Deterministic fork test failed: holder_rc=$fork_holder_rc waiter_rc=$fork_waiter_rc." >&2
  cat "$tmp_dir/fork-holder.err" "$tmp_dir/fork-waiter.err" >&2
  exit 1
fi

if ! grep -Eq '23514|must reference current head' "$tmp_dir/fork-waiter.err"; then
  echo "Fork waiter failed for an unexpected reason." >&2
  cat "$tmp_dir/fork-waiter.err" >&2
  exit 1
fi

fork_holder_id="$(tail -n 1 "$tmp_dir/fork-holder.out")"
fork_readback="$("${psql_base[@]}" <<SQL
select
  count(*) filter (
    where supersedes_event_id = '${seed_id}'::uuid
       or acknowledges_event_id = '${seed_id}'::uuid
  ),
  max(event_id) filter (where operation_id = '${fork_holder_op}'),
  (
    select event_id
    from r9a0_coordination.latest_thread_state
    where thread_key = '${fork_thread}'
  )
from r9a0_coordination.events
where thread_key = '${fork_thread}';
SQL
)"

IFS='|' read -r child_count persisted_holder_id projected_id <<<"$fork_readback"
if [[ "$child_count" != "1" ||
      "$fork_holder_id" != "$persisted_holder_id" ||
      "$persisted_holder_id" != "$projected_id" ]]; then
  echo "Fork readback failed: child_count=$child_count holder=$fork_holder_id persisted=$persisted_holder_id projected=$projected_id" >&2
  exit 1
fi

idem_thread="r9a0/test/two-session-idempotency-${suffix}"
idem_op="r9a0-concurrency-idempotency-${suffix}"
idem_holder_app="r9a0-idem-holder-${suffix}"
idem_waiter_app="r9a0-idem-waiter-${suffix}"
idem_ready_file="$tmp_dir/idem-holder-ready"
idem_release_file="$tmp_dir/idem-holder-release"

run_idempotency_holder() {
  PGAPPNAME="$idem_holder_app" "${psql_base[@]}" <<SQL
select set_config('request.jwt.claim.role', 'service_role', false);
begin;
select pg_catalog.pg_advisory_xact_lock(
  pg_catalog.hashtextextended('r9a0-operation:${idem_op}', 0)
);
\! touch '$idem_ready_file'
\! while [ ! -f '$idem_release_file' ]; do sleep 0.05; done
with receipt as (
  select r9a0_api.append_coordination_event(
    '${idem_op}',
    '${idem_thread}',
    'test/idempotency-session',
    'test/concurrency-review',
    'STATUS',
    'IN_PROGRESS',
    'Insert one event while the second session is blocked on the same operation lock.',
    'The holder must return INSERTED and the waiter must return EXISTING.',
    null,
    null,
    null,
    '{"synthetic":true,"test":"two-session-idempotency"}'::jsonb,
    '{"disposable_database_required":true,"barrier":"advisory-lock"}'::jsonb
  ) as value
)
select (value->>'result') || '|' || (value->>'event_id')
from receipt;
commit;
SQL
}

run_idempotency_waiter() {
  PGAPPNAME="$idem_waiter_app" "${psql_base[@]}" <<SQL
select set_config('request.jwt.claim.role', 'service_role', false);
with receipt as (
  select r9a0_api.append_coordination_event(
    '${idem_op}',
    '${idem_thread}',
    'test/idempotency-session',
    'test/concurrency-review',
    'STATUS',
    'IN_PROGRESS',
    'Insert one event while the second session is blocked on the same operation lock.',
    'The holder must return INSERTED and the waiter must return EXISTING.',
    null,
    null,
    null,
    '{"synthetic":true,"test":"two-session-idempotency"}'::jsonb,
    '{"disposable_database_required":true,"barrier":"advisory-lock"}'::jsonb
  ) as value
)
select (value->>'result') || '|' || (value->>'event_id')
from receipt;
SQL
}

run_idempotency_holder >"$tmp_dir/idem-holder.out" 2>"$tmp_dir/idem-holder.err" &
idem_holder_pid=$!
wait_for_file "$idem_ready_file" "idempotency holder lock acquisition"

run_idempotency_waiter >"$tmp_dir/idem-waiter.out" 2>"$tmp_dir/idem-waiter.err" &
idem_waiter_pid=$!
wait_for_advisory_waiter "$idem_waiter_app" "idempotency waiter"
touch "$idem_release_file"

set +e
wait "$idem_holder_pid"
idem_holder_rc=$?
wait "$idem_waiter_pid"
idem_waiter_rc=$?
set -e

if [[ "$idem_holder_rc" -ne 0 || "$idem_waiter_rc" -ne 0 ]]; then
  echo "Deterministic idempotency test failed: holder_rc=$idem_holder_rc waiter_rc=$idem_waiter_rc." >&2
  cat "$tmp_dir/idem-holder.err" "$tmp_dir/idem-waiter.err" >&2
  exit 1
fi

holder_line="$(tail -n 1 "$tmp_dir/idem-holder.out")"
waiter_line="$(tail -n 1 "$tmp_dir/idem-waiter.out")"
holder_type="${holder_line%%|*}"
waiter_type="${waiter_line%%|*}"
holder_id="${holder_line#*|}"
waiter_id="${waiter_line#*|}"

if [[ "$holder_type" != "INSERTED" || "$waiter_type" != "EXISTING" ]]; then
  echo "Idempotency receipts were not deterministic: holder=$holder_type waiter=$waiter_type" >&2
  exit 1
fi

if [[ "$holder_id" != "$waiter_id" ]]; then
  echo "Idempotency sessions returned different event IDs: $holder_id vs $waiter_id" >&2
  exit 1
fi

idem_count="$("${psql_base[@]}" <<SQL
select count(*)
from r9a0_coordination.events
where operation_id = '${idem_op}';
SQL
)"
idem_count="$(printf '%s\n' "$idem_count" | tail -n 1)"

if [[ "$idem_count" != "1" ]]; then
  echo "Idempotency test persisted $idem_count rows; expected exactly one." >&2
  exit 1
fi

echo "PASS: deterministic two-session fork serialization and idempotency overlap were verified."
echo "The disposable database now contains synthetic test rows and must be reset or destroyed."
