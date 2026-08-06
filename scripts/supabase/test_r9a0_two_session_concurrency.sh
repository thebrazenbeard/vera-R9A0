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
fork_thread="r9a0/test/two-session-fork-${suffix}"
fork_seed_op="r9a0-concurrency-seed-${suffix}"
fork_op_a="r9a0-concurrency-fork-a-${suffix}"
fork_op_b="r9a0-concurrency-fork-b-${suffix}"

psql_base=(psql "$R9A0_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1)

"${psql_base[@]}" <<'SQL' >/dev/null
select to_regprocedure(
  'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)'
) is not null;
SQL

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
    'Create the committed predecessor for the two-session fork race.',
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

run_fork_candidate() {
  local operation_id="$1"
  local source_address="$2"

  "${psql_base[@]}" <<SQL
\set VERBOSITY verbose
select set_config('request.jwt.claim.role', 'service_role', false);
begin;
select r9a0_api.append_coordination_event(
  '${operation_id}',
  '${fork_thread}',
  '${source_address}',
  'test/concurrency-review',
  'STATUS',
  'IN_PROGRESS',
  'Race to advance the same committed predecessor.',
  'Exactly one concurrent session may become the controlling successor.',
  null,
  '${seed_id}'::uuid,
  null,
  '{"synthetic":true,"test":"two-session-fork"}'::jsonb,
  '{"disposable_database_required":true}'::jsonb
);
commit;
SQL
}

run_fork_candidate "$fork_op_a" "test/session-a" >"$tmp_dir/fork-a.out" 2>"$tmp_dir/fork-a.err" &
pid_a=$!
run_fork_candidate "$fork_op_b" "test/session-b" >"$tmp_dir/fork-b.out" 2>"$tmp_dir/fork-b.err" &
pid_b=$!

set +e
wait "$pid_a"
rc_a=$?
wait "$pid_b"
rc_b=$?
set -e

success_count=0
[[ "$rc_a" -eq 0 ]] && success_count=$((success_count + 1))
[[ "$rc_b" -eq 0 ]] && success_count=$((success_count + 1))

if [[ "$success_count" -ne 1 ]]; then
  echo "Fork race failed: expected exactly one successful session, got $success_count." >&2
  cat "$tmp_dir/fork-a.err" "$tmp_dir/fork-b.err" >&2
  exit 1
fi

loser_err="$tmp_dir/fork-a.err"
winner_op="$fork_op_b"
if [[ "$rc_a" -eq 0 ]]; then
  loser_err="$tmp_dir/fork-b.err"
  winner_op="$fork_op_a"
fi

if ! grep -Eq '23514|must reference current head' "$loser_err"; then
  echo "Fork race failed for an unexpected reason." >&2
  cat "$loser_err" >&2
  exit 1
fi

fork_readback="$("${psql_base[@]}" <<SQL
select
  count(*) filter (
    where supersedes_event_id = '${seed_id}'::uuid
       or acknowledges_event_id = '${seed_id}'::uuid
  ),
  max(event_id) filter (where operation_id = '${winner_op}'),
  (
    select event_id
    from r9a0_coordination.latest_thread_state
    where thread_key = '${fork_thread}'
  )
from r9a0_coordination.events
where thread_key = '${fork_thread}';
SQL
)"

IFS='|' read -r child_count winner_id projected_id <<<"$fork_readback"
if [[ "$child_count" != "1" || "$winner_id" != "$projected_id" ]]; then
  echo "Fork readback failed: child_count=$child_count winner=$winner_id projected=$projected_id" >&2
  exit 1
fi

idem_thread="r9a0/test/two-session-idempotency-${suffix}"
idem_op="r9a0-concurrency-idempotency-${suffix}"

run_idempotent_candidate() {
  "${psql_base[@]}" <<SQL
select set_config('request.jwt.claim.role', 'service_role', false);
with receipt as (
  select r9a0_api.append_coordination_event(
    '${idem_op}',
    '${idem_thread}',
    'test/idempotency-session',
    'test/concurrency-review',
    'STATUS',
    'IN_PROGRESS',
    'Race the same operation ID through two database sessions.',
    'Both sessions must resolve to one persisted event.',
    null,
    null,
    null,
    '{"synthetic":true,"test":"two-session-idempotency"}'::jsonb,
    '{"disposable_database_required":true}'::jsonb
  ) as value
)
select (value->>'result') || '|' || (value->>'event_id')
from receipt;
SQL
}

run_idempotent_candidate >"$tmp_dir/idem-a.out" 2>"$tmp_dir/idem-a.err" &
pid_a=$!
run_idempotent_candidate >"$tmp_dir/idem-b.out" 2>"$tmp_dir/idem-b.err" &
pid_b=$!

set +e
wait "$pid_a"
rc_a=$?
wait "$pid_b"
rc_b=$?
set -e

if [[ "$rc_a" -ne 0 || "$rc_b" -ne 0 ]]; then
  echo "Idempotency race failed: both sessions must succeed." >&2
  cat "$tmp_dir/idem-a.err" "$tmp_dir/idem-b.err" >&2
  exit 1
fi

line_a="$(tail -n 1 "$tmp_dir/idem-a.out")"
line_b="$(tail -n 1 "$tmp_dir/idem-b.out")"
type_a="${line_a%%|*}"
type_b="${line_b%%|*}"
id_a="${line_a#*|}"
id_b="${line_b#*|}"

if [[ "$id_a" != "$id_b" ]]; then
  echo "Idempotency race returned different event IDs: $id_a vs $id_b" >&2
  exit 1
fi

types="$(printf '%s\n%s\n' "$type_a" "$type_b" | sort | tr '\n' ' ')"
if [[ "$types" != "EXISTING INSERTED " ]]; then
  echo "Idempotency race returned unexpected receipt types: $types" >&2
  exit 1
fi

idem_count="$("${psql_base[@]}" <<SQL
select count(*)
from r9a0_coordination.events
where operation_id = '${idem_op}';
SQL
)"

if [[ "$idem_count" != "1" ]]; then
  echo "Idempotency race persisted $idem_count rows; expected exactly one." >&2
  exit 1
fi

echo "PASS: two-session fork serialization and concurrent idempotency were verified."
echo "The disposable database now contains synthetic test rows and must be reset or destroyed."
