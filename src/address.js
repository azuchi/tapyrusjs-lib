'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const networks = require('./networks');
const payments = require('./payments');
const bscript = require('./script');
const types = require('./types');
const bech32 = require('bech32');
const bs58check = require('bs58check');
const typeforce = require('typeforce');
const PUBKEY_HASH_LENGTH = 20;
const COLOR_ID_LENGTH = 33;
const UNCOLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH; // 21
const COLORED_LENGTH = 1 + PUBKEY_HASH_LENGTH + COLOR_ID_LENGTH; // 54
function fromBase58Check(address) {
  const payload = bs58check.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < UNCOLORED_LENGTH)
    throw new TypeError(`${address} is too short(${payload.length})`);
  if (payload.length > COLORED_LENGTH)
    throw new TypeError(`${address} is too long(${payload.length})`);
  const version = payload.readUInt8(0);
  if (payload.length > UNCOLORED_LENGTH) {
    // Colored
    const colorId = payload.slice(1, 1 + COLOR_ID_LENGTH);
    const hash = payload.slice(1 + COLOR_ID_LENGTH);
    if (hash.length !== PUBKEY_HASH_LENGTH) {
      throw new TypeError(`Invalid hash(${hash})`);
    }
    return { version, colorId, hash };
  } else {
    // Uncolored
    const hash = payload.slice(1);
    return { version, hash };
  }
}
exports.fromBase58Check = fromBase58Check;
function fromBech32(address) {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));
  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}
exports.fromBech32 = fromBech32;
function toBase58Check(hash, version, colorId) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);
  const payload = colorId
    ? Buffer.allocUnsafe(COLORED_LENGTH)
    : Buffer.allocUnsafe(UNCOLORED_LENGTH);
  payload.writeUInt8(version, 0);
  if (colorId) {
    colorId.copy(payload, 1);
    hash.copy(payload, 1 + COLOR_ID_LENGTH);
  } else {
    hash.copy(payload, 1);
  }
  return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32.toWords(data);
  words.unshift(version);
  return bech32.encode(prefix, words);
}
exports.toBech32 = toBech32;
function fromOutputScript(output, network) {
  try {
    const payment = payments.util.fromOutputScript(output, network);
    return payment.address;
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
  network = network || networks.prod;
  let decodeBase58;
  let decodeBech32;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.coloredPubKeyHash)
      return payments.cp2pkh({
        hash: decodeBase58.hash,
        colorId: decodeBase58.colorId,
      }).output;
    if (decodeBase58.version === network.coloredScriptHash)
      return payments.cp2sh({
        hash: decodeBase58.hash,
        colorId: decodeBase58.colorId,
      }).output;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}
    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32.data }).output;
        if (decodeBech32.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32.data }).output;
      }
    }
  }
  throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;
