#!/usr/bin/env bash
set -euo pipefail

# Resolve every path from this script so it works from any current directory.
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
v8_dir="$script_dir/v8-vulnerable/v8"
out_name="out/x64.release"
out_dir="$v8_dir/$out_name"
gn_bin="$v8_dir/buildtools/linux64/gn"
ninja_bin="$v8_dir/third_party/ninja/ninja"

if [[ ! -d "$v8_dir" ]]; then
  echo "[-] V8 source directory not found: $v8_dir" >&2
  exit 1
fi

if [[ ! -x "$gn_bin" ]]; then
  echo "[-] bundled GN executable not found: $gn_bin" >&2
  echo "[-] run gclient sync for the V8 checkout and try again" >&2
  exit 1
fi

if [[ ! -x "$ninja_bin" ]]; then
  echo "[-] bundled Ninja executable not found: $ninja_bin" >&2
  echo "[-] run gclient sync for the V8 checkout and try again" >&2
  exit 1
fi

# Exact GN configuration used by the d8 exploit chain.
gn_args='is_component_build=false
is_debug=false
target_cpu="x64"
v8_enable_sandbox=true
v8_enable_backtrace=true
v8_enable_disassembler=true
v8_enable_object_print=true
v8_enable_verify_heap=true
dcheck_always_on=false
use_siso=false'

cd "$v8_dir"

echo "[*] Generating $out_name for the exploit chain"
"$gn_bin" gen "$out_name" --args="$gn_args"

echo "[*] Building d8"
"$ninja_bin" -C "$out_name" d8

echo "[+] Build completed: $out_dir/d8"

if command -v readelf >/dev/null 2>&1; then
  build_id=$(readelf -n "$out_dir/d8" 2>/dev/null |
    awk '/Build ID:/ {print $3; exit}')
  if [[ -n "$build_id" ]]; then
    echo "[+] d8 build ID: $build_id"
  fi
fi

echo '[+] Run the exploit chain with:'
printf '    %s\n' "$script_dir/run_rce.sh"
