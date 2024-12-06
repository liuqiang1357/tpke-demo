import crypto from 'crypto';
import { Fp, Fp2 } from '@noble/curves/abstract/tower';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { randBetween } from 'bigint-crypto-utils';

export function getConsensusThreshold(consensusSize: number): number {
  return consensusSize - Math.floor((consensusSize - 1) / 3);
}

export function getScaler(_size: number, _threshold: number): bigint {
  throw new Error('Unimplemented');
}

export function randScalar(): bigint {
  return randBetween(bls.G1.CURVE.n);
}

export function randG1(): ProjPointType<Fp> {
  // const s = BigInt('13142576477868579383218672883803438445527974108075655005925877124647713243145');
  const s = randScalar();
  return bls.G1.ProjectivePoint.BASE.multiply(s);
}

class BlsCipherText {
  constructor(
    public cMsg: ProjPointType<Fp>,
    public bigR: ProjPointType<Fp>,
    public commitment: ProjPointType<Fp2>,
  ) {}

  verify(): boolean {
    throw new Error('Unimplemented');
  }

  toBytes(): Uint8Array {
    return Buffer.concat([
      this.cMsg.toRawBytes(),
      this.bigR.toRawBytes(),
      this.commitment.toRawBytes(),
    ]);
  }
}

export function blsEncrypt(msg: ProjPointType<Fp>, pk: ProjPointType<Fp>): BlsCipherText {
  const r = randScalar();
  // const r = BigInt('26241604929413036610059529953849322917897934190194857549647694249968225593684');

  // C=M+rpk, R1=rG1, R2=-rG2
  const rpk = pk.multiply(r);
  const cMsg = msg.add(rpk);

  const bigR1 = bls.G1.ProjectivePoint.BASE.multiply(r);
  const bigR2 = bls.G2.ProjectivePoint.BASE.multiply(r).negate();

  return new BlsCipherText(cMsg, bigR1, bigR2);
}

export function aesEncrypt(msg: Uint8Array, key: ProjPointType<Fp>): Uint8Array {
  if (msg.length < 1) {
    throw new Error('Empty aes message');
  }
  const seed = key.toRawBytes(false);

  const hash = crypto.createHash('sha256').update(seed).digest();

  const cipher = crypto.createCipheriv('aes-256-cbc', hash, hash.subarray(0, 16));

  let encrypted = cipher.update(msg);

  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return encrypted;
}

export class PublicKey {
  constructor(public g1: ProjPointType<Fp>) {}

  static createGlobalPublicKey(
    _aggregatedCommitment: Uint8Array,
    _consensusSize: number,
  ): PublicKey {
    throw new Error('Unimplemented');
  }

  static fromHex(hex: string): PublicKey {
    const g1 = bls.G1.ProjectivePoint.fromHex(hex);
    return new PublicKey(g1);
  }

  encrypt(msg: Uint8Array): { encryptedKey: Uint8Array; encryptedMsg: Uint8Array } {
    const aesKeyG1 = randG1();

    const encryptedKey = blsEncrypt(aesKeyG1, this.g1);

    const encryptedMsg = aesEncrypt(msg, aesKeyG1);

    return { encryptedKey: encryptedKey.toBytes(), encryptedMsg };
  }
}
