import { mnemonicNew, mnemonicToPrivateKey } from '@ton/crypto';
import { beginCell, Address } from '@ton/core';
import { signData } from './sign';
import { verifySignData } from './verify';

/**
 * TON Connect data signing demonstration
 * 
 * Supports three data types:
 * 1. Text - for simple text messages
 * 2. Binary - for arbitrary data
 * 3. TON Cell - for special TON data structures
 */

// Initialization
const keyPair = await mnemonicToPrivateKey(await mnemonicNew());
const domain = 'app.example.com';
const address = 'UQCyqTmXJpshFu1GW1tyTX6paa3c-37OG9s3uv8ZzX_9GDfx';

// ============= 1. Text Data =============
console.log('\n1. Signing text message:');
const textSignedData = signData({
    payload: {
        type: 'text',
        text: 'Hello, TON!',
    },
    domain,
    privateKey: keyPair.secretKey,
    address,
});
console.log('Signature:', textSignedData.signature);
console.log(
    'Valid:',
    verifySignData({ signedData: textSignedData, publicKey: keyPair.publicKey })
);

// ============= 2. Binary Data =============
console.log('\n2. Signing binary data:');
const binarySignedData = signData({
    payload: {
        type: 'binary',
        bytes: Buffer.from('🌟 Binary TON Data 🚀').toString('base64'),
    },
    domain,
    privateKey: keyPair.secretKey,
    address,
});
console.log('Signature:', binarySignedData.signature);
console.log(
    'Valid:',
    verifySignData({
        signedData: binarySignedData,
        publicKey: keyPair.publicKey,
    })
);

// ============= 3. TON Cell Data =============
console.log('\n3. Signing TON Cell:');

// Create Cell with transaction data
const cell = beginCell()
    .storeUint(0x123, 32) // transaction op-code
    .storeCoins(1_000_000_000n) // amount: 1 TON
    .storeAddress(Address.parse(address)) // recipient address
    .storeStringTail('Transfer 1 TON') // transaction comment
    .endCell();

// Sign the Cell
const cellSignedData = signData({
    payload: {
        type: 'cell',
        // TL-B schema describes cell structure
        schema: 'transfer#123 amount:Coins to:MsgAddress comment:string = Transfer',
        cell: cell.toBoc().toString('base64'),
    },
    domain,
    privateKey: keyPair.secretKey,
    address,
});
console.log('Signature:', cellSignedData.signature);
console.log(
    'Valid:',
    verifySignData({ signedData: cellSignedData, publicKey: keyPair.publicKey })
);
