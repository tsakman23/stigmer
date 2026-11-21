#!/usr/bin/env bash
# Usage: check-commit-messages.sh <base> <head>
# Fails unless every non-merge commit subject in <base>..<head> is a Conventional Commit.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base> <head>" >&2
  exit 2
fi
base="$1"
head="$2"

subject_re='^(feat|fix|refactor|test|docs|chore|ci|perf|build)(\([a-z0-9-]+\))?!?: .{1,72}$'

bad=0
count=0
while IFS=$'\t' read -r sha subject; do
  count=$((count + 1))
  if ! [[ "$subject" =~ $subject_re ]]; then
    echo "error: commit ${sha:0:12} has invalid subject: '$subject'" >&2
    echo "  rule: must match $subject_re" >&2
    bad=$((bad + 1))
  fi
done < <(git log --no-merges --format=$'%H\t%s' "$base..$head")

if [[ $bad -gt 0 ]]; then
  echo "$bad of $count commit(s) violate the Conventional Commits rule" >&2
  exit 1
fi
echo "commit messages ok: $count commit(s) in $base..$head"
