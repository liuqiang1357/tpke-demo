import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { PublicKey } from './tpke';

async function buildTransaction() {
  const privateKey = '0xc4ddeed5bd53f154151029b4a171f1dc68d9973dd831c0eecc77661656ae3b07';
  const account = privateKeyToAccount(privateKey);

  const transaction = {
    chainId: 2312251829,
    to: account.address,
    nonce: 0,
    gasPrice: BigInt(400_0000_0000),
    gas: BigInt(2_1000),
    value: BigInt(1),
  };

  return await account.signTransaction(transaction);
}

describe('PublicKey', () => {
  test('fromBytes and toBytes works', () => {
    const publicKey = PublicKey.fromBytes(
      Buffer.from(
        'a5aa188d1c60a7173e59fe49b68b969999e70aa4c1acb76c5a3dd2ad0d19a859b1a2759e3995ce1ceccdea5a57fbf637',
        'hex',
      ),
    );
    expect(Buffer.from(publicKey.toBytes()).toString('hex')).toBe(
      'a5aa188d1c60a7173e59fe49b68b969999e70aa4c1acb76c5a3dd2ad0d19a859b1a2759e3995ce1ceccdea5a57fbf637',
    );
  });

  test('create works', () => {
    const publicKey = PublicKey.create(
      Buffer.from(
        '0000000000000000000000000000000004f1c7e8d68052701518e38b4b64a55e1ce35392f13b773bcda20a54a386e83a47641b98c7abf3d8212061c16604ca9100000000000000000000000000000000071f445019d9e972465b04eee6cc5e842829f4103eeabe0e814c997034efbf4082f7505a53a39edf8efc61157bf4de66',
        'hex',
      ),
      7,
    );
    expect(Buffer.from(publicKey.toBytes()).toString('hex')).toBe(
      '84c7a302bd8fdd14c297c82f57db8788038489c8325574dad73cc4ceea2f30c673fe3558b3ef5df28d87f4ef4fd18c36',
    );
  });

  test('encrypt works', async () => {
    const transaction = await buildTransaction();

    const publicKey = PublicKey.fromBytes(
      Buffer.from(
        'a5aa188d1c60a7173e59fe49b68b969999e70aa4c1acb76c5a3dd2ad0d19a859b1a2759e3995ce1ceccdea5a57fbf637',
        'hex',
      ),
    );

    const { encryptedKey, encryptedMsg } = publicKey.encrypt(
      Buffer.from(transaction.slice(2), 'hex'),
    );

    const envelopeData = Buffer.concat([
      Buffer.from([0xff, 0xff, 0xff, 0xff]),
      encryptedKey,
      encryptedMsg,
    ]);

    // eslint-disable-next-line no-console
    console.log(
      `encryptedKey: %s\necryptedMsg: %s\nenvelopeData: 0x%s\nencrypted tx hash:%s\n`,
      Buffer.from(encryptedKey).toString('hex'),
      Buffer.from(encryptedMsg).toString('hex'),
      envelopeData.toString('hex'),
      keccak256(transaction),
    );
  });
});
