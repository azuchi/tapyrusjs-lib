'use strict';
// {signature}
Object.defineProperty(exports, '__esModule', { value: true });
exports.check = check;
const bscript = require('../../script');
function check(script) {
  const chunks = bscript.decompile(script);
  return chunks.length === 1 && bscript.isCanonicalScriptSignature(chunks[0]);
}
check.toJSON = () => {
  return 'pubKey input';
};
