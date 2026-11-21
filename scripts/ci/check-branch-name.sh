#!/usr/bin/env bash
# Usage: check-branch-name.sh <branch-name>
# Fails unless the branch name follows the repo convention (see CONTRIBUTING.md).
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <branch-name>" >&2
  exit 2
fi
branch="$1"

task_re='^(feat|fix|refactor|test|docs|chore|ci)/m[0-9]+-t[0-9]{2}-[a-z0-9]+(-[a-z0-9]+)*$'
milestone_re='^milestone/m[0-9]+-[a-z0-9-]+$'
dependabot_re='^dependabot/'

if [[ "$branch" =~ $task_re || "$branch" =~ $milestone_re || "$branch" =~ $dependabot_re ]]; then
  echo "branch name ok: $branch"
  exit 0
fi

{
  echo "error: invalid branch name: '$branch'"
  echo "allowed forms:"
  echo "  <feat|fix|refactor|test|docs|chore|ci>/m<N>-t<NN>-<slug>   matching $task_re"
  echo "  milestone/m<N>-<slug>                                      matching $milestone_re"
  echo "  dependabot/...                                             matching $dependabot_re"
} >&2
exit 1
