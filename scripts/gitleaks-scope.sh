#!/usr/bin/env bash
set -euo pipefail

GITLEAKS_SCOPE_TMP=""

cleanup() {
  if [ -n "$GITLEAKS_SCOPE_TMP" ] && [ -d "$GITLEAKS_SCOPE_TMP" ]; then
    rm -rf -- "$GITLEAKS_SCOPE_TMP"
  fi
}

scan() {
  local source="$1"
  local log_opts="$2"
  local baseline="${3:-}"
  local args=(detect --source "$source" --log-opts "$log_opts" --redact --no-banner --exit-code 1)
  if [ -n "$baseline" ]; then
    args+=(--baseline-path "$baseline")
  fi
  if [ -f "$source/.gitleaks.toml" ]; then
    args+=(--config "$source/.gitleaks.toml")
  fi
  gitleaks "${args[@]}"
}

require_commit() {
  git rev-parse --verify --quiet "$1^{commit}" >/dev/null || {
    echo "gitleaks-scope: required commit is unavailable: $1" >&2
    exit 2
  }
}

self_test() {
  local test_repo main_sha abandoned_sha clean_head leaked_head
  test_repo="$(mktemp -d)"
  GITLEAKS_SCOPE_TMP="$test_repo"
  trap cleanup EXIT

  git -C "$test_repo" init -q -b main
  git -C "$test_repo" config user.name gitleaks-scope-test
  git -C "$test_repo" config user.email gitleaks-scope@example.invalid
  printf 'clean\n' >"$test_repo/README.md"
  git -C "$test_repo" add README.md
  git -C "$test_repo" commit -qm 'clean main'
  main_sha="$(git -C "$test_repo" rev-parse HEAD)"

  git -C "$test_repo" switch -qc abandoned
  printf 'aws_access_key_id = AKIA%s\n' 'ABCDEFGHIJKLMNOP' >"$test_repo/abandoned.txt"
  git -C "$test_repo" add abandoned.txt
  git -C "$test_repo" commit -qm 'abandoned leak'
  abandoned_sha="$(git -C "$test_repo" rev-parse HEAD)"

  git -C "$test_repo" switch -qc feature "$main_sha"
  printf 'still clean\n' >"$test_repo/feature.txt"
  git -C "$test_repo" add feature.txt
  git -C "$test_repo" commit -qm 'clean feature'
  clean_head="$(git -C "$test_repo" rev-parse HEAD)"

  scan "$test_repo" "$main_sha..$clean_head"
  echo "negative control: scoped scan ignores unrelated ref"

  if scan "$test_repo" "$abandoned_sha" >/dev/null 2>&1; then
    echo "negative control: protected history accepted a leak" >&2
    exit 1
  fi
  echo "negative control: protected history rejects a leak"

  if scan "$test_repo" --all >/dev/null 2>&1; then
    echo "negative control: all-ref scan accepted a leak" >&2
    exit 1
  fi
  echo "negative control: all-ref scan rejects a leak"

  printf 'aws_access_key_id = AKIA%s\n' 'PONMLKJIHGFEDCBA' >"$test_repo/feature-leak.txt"
  git -C "$test_repo" add feature-leak.txt
  git -C "$test_repo" commit -qm 'feature leak'
  leaked_head="$(git -C "$test_repo" rev-parse HEAD)"
  if scan "$test_repo" "$clean_head..$leaked_head" >/dev/null 2>&1; then
    echo "negative control: exact change range accepted a leak" >&2
    exit 1
  fi
  echo "negative control: exact change range rejects a leak"
  cleanup
  GITLEAKS_SCOPE_TMP=""
  trap - EXIT
}

case "${1:-}" in
  scoped)
    [ "$#" -eq 4 ] || {
      echo "usage: $0 scoped MAIN_REF BASE_SHA HEAD_SHA" >&2
      exit 2
    }
    require_commit "$2"
    require_commit "$3"
    require_commit "$4"
    scan . "$2" .gitleaks-baseline.json
    scan . "$3..$4" .gitleaks-baseline.json
    ;;
  full)
    [ "$#" -eq 1 ] || {
      echo "usage: $0 full" >&2
      exit 2
    }
    scan . --all .gitleaks-baseline.json
    ;;
  self-test)
    [ "$#" -eq 1 ] || {
      echo "usage: $0 self-test" >&2
      exit 2
    }
    self_test
    ;;
  *)
    echo "usage: $0 {scoped MAIN_REF BASE_SHA HEAD_SHA|full|self-test}" >&2
    exit 2
    ;;
esac
