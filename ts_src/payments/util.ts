import { Network } from '../networks';

import * as bcrypto from '../crypto';
import * as networks from '../networks';
import * as payments from '../payments';
import * as bscript from '../script';
import { Payment, PaymentFunction, Stack, StackFunction } from './index';
import * as lazy from './lazy';
const bs58check = require('bs58check');

export function fromOutputScript(output: Buffer, network?: Network): Payment {
  network = network || networks.prod;

  try {
    return payments.p2pkh({ output, network });
  } catch (e) {}
  try {
    return payments.p2sh({ output, network });
  } catch (e) {}
  try {
    return payments.p2wpkh({ output, network });
  } catch (e) {}
  try {
    return payments.p2wsh({ output, network });
  } catch (e) {}
  try {
    return payments.cp2pkh({ output, network });
  } catch (e) {}
  try {
    return payments.cp2sh({ output, network });
  } catch (e) {}

  throw new Error(bscript.toASM(output) + ' is not standard script');
}

export function addressFn(
  address: string,
): () => { version: number; hash: Buffer } {
  return lazy.value(() => {
    const payload = bs58check.decode(address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
}
export function coloredAddressFn(
  address: string,
): () => {
  version: number;
  colorId: Buffer;
  hash: Buffer;
} {
  return lazy.value(() => {
    const payload = bs58check.decode(address);
    const version = payload.readUInt8(0);
    const colorId = payload.slice(1, 34);
    const hash = payload.slice(34);
    return { version, colorId, hash };
  });
}

export function chunksFn(script: Buffer): StackFunction {
  return lazy.value(() => {
    return bscript.decompile(script);
  }) as StackFunction;
}

export function redeemFn(
  a: Payment,
  network: Network | undefined,
): PaymentFunction {
  return lazy.value(
    (): Payment => {
      const chunks = chunksFn(a.input!)();
      return {
        network,
        output: chunks[chunks.length - 1] as Buffer,
        input: bscript.compile(chunks.slice(0, -1)),
        witness: a.witness || [],
      };
    },
  ) as PaymentFunction;
}

export function checkHash(hash: Buffer, hash2: Buffer): void {
  if (hash.length > 0 && !hash.equals(hash2))
    throw new TypeError('Hash mismatch');
}

export function validColorId(colorId: Buffer, newColorId: Buffer): Buffer {
  if (colorId.length > 0 && !colorId.equals(newColorId))
    throw new TypeError('ColorId mismatch');
  return newColorId;
}

export function stacksEqual(a: Buffer[], b: Buffer[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}

export function checkInput(
  _chunksFn: StackFunction,
  _redeemFn: PaymentFunction,
  hashForCheck: Buffer,
): Buffer | null {
  const chunks = _chunksFn();
  if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
  const redeem = _redeemFn();
  if (!Buffer.isBuffer(redeem.output)) throw new TypeError('Input is invalid');

  return _checkRedeem(redeem, hashForCheck);
}

export function checkWitness(a: Payment): void {
  if (a.witness) {
    if (
      a.redeem &&
      a.redeem.witness &&
      !stacksEqual(a.redeem.witness, a.witness)
    )
      throw new TypeError('Witness and redeem.witness mismatch');
  }
}

export function checkRedeem(
  a: Payment,
  network: Network,
  _redeemFn: PaymentFunction,
  hashForCheck: Buffer,
): void {
  if (a.redeem) {
    if (a.redeem.network && a.redeem.network !== network)
      throw new TypeError('Network mismatch');
    if (a.input) {
      const redeem = _redeemFn();
      if (a.redeem.output && !a.redeem.output.equals(redeem.output!))
        throw new TypeError('Redeem.output mismatch');
      if (a.redeem.input && !a.redeem.input.equals(redeem.input!))
        throw new TypeError('Redeem.input mismatch');
    }

    _checkRedeem(a.redeem, hashForCheck);
  }
}

// inlined to prevent 'no-inner-declarations' failing
function _checkRedeem(redeem: Payment, hashForCheck: Buffer): Buffer | null {
  let hash2 = null;
  // is the redeem output empty/invalid?
  if (redeem.output) {
    const decompile = bscript.decompile(redeem.output);
    if (!decompile || decompile.length < 1)
      throw new TypeError('Redeem.output too short');

    // match hash against other sources
    hash2 = bcrypto.hash160(redeem.output);
    checkHash(hashForCheck, hash2);
  }

  if (redeem.input) {
    const hasInput = redeem.input.length > 0;
    const hasWitness = redeem.witness && redeem.witness.length > 0;
    if (!hasInput && !hasWitness) throw new TypeError('Empty input');
    if (hasInput && hasWitness)
      throw new TypeError('Input and witness provided');
    if (hasInput) {
      const richunks = bscript.decompile(redeem.input) as Stack;
      if (!bscript.isPushOnly(richunks))
        throw new TypeError('Non push-only scriptSig');
    }
  }
  return hash2;
}
