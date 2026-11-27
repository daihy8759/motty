#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
viva_dir="$here/../viva"
out_dir=${1:-"$here/build/apple-silicon"}

if [[ $# -gt 1 ]]; then
	echo "usage: $0 [output-directory]" >&2
	exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
	echo "build-macos-arm64.sh must run on macOS" >&2
	exit 1
fi

if ! git -C "$viva_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "expected a Viva checkout at $viva_dir" >&2
	exit 1
fi

if [[ "$(git -C "$viva_dir" branch --show-current)" != main ]]; then
	echo "Viva must be on its main branch before it can be updated" >&2
	exit 1
fi

if [[ -n "$(git -C "$viva_dir" status --porcelain)" ]]; then
	echo "Viva has local changes; commit or stash them before building" >&2
	exit 1
fi

go_command=$(command -v go || true)
if [[ -z "$go_command" ]]; then
	echo "Go was not found in PATH" >&2
	exit 1
fi

git -C "$viva_dir" fetch origin +refs/heads/main:refs/remotes/origin/main
while ! git -C "$viva_dir" merge-base --is-ancestor HEAD origin/main 2>/dev/null; do
	if [[ "$(git -C "$viva_dir" rev-parse --is-shallow-repository)" != true ]]; then
		echo "Viva main does not contain the current checkout; refusing to replace it" >&2
		exit 1
	fi
	git -C "$viva_dir" fetch --deepen=100 origin +refs/heads/main:refs/remotes/origin/main
done
git -C "$viva_dir" merge --ff-only origin/main

case "$out_dir" in
	/*) ;;
	*) out_dir="$here/$out_dir" ;;
esac
mkdir -p "$out_dir"

(
	cd "$viva_dir"
	"$go_command" run ./cmd/viva package \
		-C "$here" \
		--target darwin \
		--arch arm64 \
		--format app,zip,dmg \
		-o "$out_dir/Motty.app" \
		--sign-identity -
)
