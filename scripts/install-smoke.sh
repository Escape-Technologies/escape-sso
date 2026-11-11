#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tag> [--from <path>]" >&2
  exit 2
fi

tag=$1
shift
source_ref="github:Escape-Technologies/escape-sso#${tag}"

if [[ $# -gt 0 ]]; then
  if [[ $# -ne 2 || $1 != "--from" ]]; then
    echo "Usage: $0 <tag> [--from <path>]" >&2
    exit 2
  fi
  source_ref="file:$(cd "$2" && pwd)"
fi

smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
cd "$smoke_dir"
npm init -y
npm install "$source_ref"
npm install @vercel/functions@3.11.1
node --input-type=module -e "import('escape-sso').then(m=>{if(typeof m.createSSO!=='function')process.exit(1)}); import('escape-sso/node'); import('escape-sso/fetch'); import('escape-sso/vercel')"
