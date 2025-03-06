# TON Connect Sign Data

Reference implementation of TON Connect sign-data protocol in TypeScript.

## Features

- Sign and verify text messages
- Sign and verify binary data
- Sign and verify cell data with TL-B schemas

## Usage

### Text Data Signing

```typescript
import { signData, verifySignData } from './src';
import { mnemonicToPrivateKey } from '@ton/crypto';

// Get key pair from your wallet
const keyPair = await mnemonicToPrivateKey(mnemonic);

const signedData = signData({
    payload: {
        type: 'text',
        text: 'Hello, TON!',
    },
    domain: 'app.example.com',
    privateKey: keyPair.secretKey,
    address: 'UQC...fx',
});

const isValid = verifySignData({
    signedData,
    publicKey: keyPair.publicKey,
});
```

### Binary Data Signing

```typescript
const signedData = signData({
    payload: {
        type: 'binary',
        bytes: Buffer.from('Binary Data').toString('base64'),
    },
    domain: 'app.example.com',
    privateKey: keyPair.secretKey,
    address: 'UQC...fx',
});
```

### TON Cell Signing

```typescript
import { beginCell, Address } from '@ton/core';

const cell = beginCell()
    .storeUint(0x123, 32) // transaction op-code
    .storeCoins(1_000_000_000n) // amount: 1 TON
    .storeAddress(Address.parse(address)) // recipient address
    .storeStringTail('Transfer 1 TON') // transaction comment
    .endCell();

const signedData = signData({
    payload: {
        type: 'cell',
        schema: 'transfer#123 amount:Coins to:MsgAddress comment:string = Transfer',
        cell: cell.toBoc().toString('base64'),
    },
    domain: 'app.example.com',
    privateKey: keyPair.secretKey,
    address: 'UQC...fx',
});
```

## Development

```bash
# Install dependencies
npm install

# Run example
npm run dev

# Run tests
npm test
```

## Testing

The project uses Vitest for testing. Tests cover all three types of payloads and various edge cases:

- Text message signing and verification
- Binary data signing and verification
- TON Cell signing and verification
- Invalid signature cases
- Message tampering detection

## License

MIT
