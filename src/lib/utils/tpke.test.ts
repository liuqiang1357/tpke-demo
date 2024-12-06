import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { PublicKey } from './tpke';

async function buildTransferForTest() {
  const privateKey = '0xc4ddeed5bd53f154151029b4a171f1dc68d9973dd831c0eecc77661656ae3b07';
  const account = privateKeyToAccount(privateKey);

  const tx = {
    chainId: 2312251829,
    to: account.address,
    nonce: 0,
    gasPrice: BigInt(400_0000_0000),
    gas: BigInt(2_1000),
    value: BigInt(1),
  };

  const serializedTx = await account.signTransaction(tx);

  return serializedTx.slice(2);
}

describe('#encryptTransaction', () => {
  test('works', async () => {
    const serializedTx = await buildTransferForTest();

    const publicKey = PublicKey.fromHex(
      'a5aa188d1c60a7173e59fe49b68b969999e70aa4c1acb76c5a3dd2ad0d19a859b1a2759e3995ce1ceccdea5a57fbf637',
    );

    const { encryptedKey, encryptedMsg } = publicKey.encrypt(Buffer.from(serializedTx, 'hex'));

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
      keccak256(`0x${serializedTx}`),
    );
  });
});
