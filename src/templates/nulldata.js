'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.output = void 0;
exports.check = check;
// OP_RETURN {data}
const bscript = require('../script');
const OPS = bscript.OPS;
function check(script) {
  const buffer = bscript.compile(script);
  return buffer.length > 1 && buffer[0] === OPS.OP_RETURN;
}
check.toJSON = () => {
  return 'null data output';
};
const output = { check };
exports.output = output;
