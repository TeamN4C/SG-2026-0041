#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
v8_dir="$script_dir/v8-vulnerable/v8"
out_name="out/x64.sandboxlab"
out_dir="$v8_dir/$out_name"
gn_bin="$v8_dir/buildtools/linux64/gn"
ninja_bin="$v8_dir/third_party/ninja/ninja"

if [[ ! -d "$v8_dir" ]]; then
  echo "[-] V8 source directory not found: $v8_dir" >&2
  exit 1
fi

if [[ ! -x "$gn_bin" ]]; then
  echo "[-] bundled GN executable not found: $gn_bin" >&2
  exit 1
fi

if [[ ! -x "$ninja_bin" ]]; then
  echo "[-] bundled Ninja executable not found: $ninja_bin" >&2
  exit 1
fi

gn_args='is_component_build=false
is_debug=false
target_cpu="x64"
v8_enable_sandbox=true
v8_enable_memory_corruption_api=true
v8_enable_backtrace=true
v8_enable_disassembler=true
v8_enable_object_print=true
dcheck_always_on=false
symbol_level=1
use_siso=false'

cd "$v8_dir"

echo "[*] Generating $out_name for Issue 554034656 diagnostics"
"$gn_bin" gen "$out_name" --args="$gn_args"

echo "[*] Building d8"
"$ninja_bin" -C "$out_name" d8

echo "[+] Build completed: $out_dir/d8"
echo '[+] Run the diagnostic PoC with:'
printf '    %s --sandbox-testing %s -- 54\n' \
  "$out_dir/d8" "$script_dir/poc_issue_554034656.js"
