import { describe, it, expect, beforeAll } from 'vitest';
import { mnemonicToPrivateKey } from '@ton/crypto';
import { signData } from '../sign';
import { verifySignData } from '../verify';
import { SignDataPayloadText, SignDataPayloadCell } from '../types';
import { beginCell } from '@ton/core';

describe('sign-data', () => {
    const TEST_MNEMONIC = [
        'unfold', 'item', 'school', 'little',
        'upper', 'surge', 'pride', 'endorse',
        'outer', 'filter', 'biology', 'prefer',
        'regular', 'island', 'hidden', 'dice',
        'nuclear', 'grace', 'motor', 'entire',
        'weird', 'between', 'falcon', 'dwarf'
    ];

    const TEST_ADDRESS = 'UQCyqTmXJpshFu1GW1tyTX6paa3c-37OG9s3uv8ZzX_9GDfx';
    const TEST_DOMAIN = 'example.com';

    let keyPair: { publicKey: Buffer; secretKey: Buffer };

    beforeAll(async () => {
        keyPair = await mnemonicToPrivateKey(TEST_MNEMONIC);
    });

    describe('text payload', () => {
        it('should sign and verify text message', () => {
            const signedData = signData({
                payload: {
                    type: 'text',
                    text: 'Hello, TON!',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(true);
        });

        it('should fail verification with wrong public key', () => {
            const signedData = signData({
                payload: {
                    type: 'text',
                    text: 'Hello, TON!',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Create invalid public key
            const wrongPublicKey = Buffer.from(keyPair.publicKey);
            wrongPublicKey[0] ^= 1; // Flip one bit

            const isValid = verifySignData({
                signedData,
                publicKey: wrongPublicKey,
            });

            expect(isValid).toBe(false);
        });

        it('should fail verification with modified message', () => {
            const signedData = signData({
                payload: {
                    type: 'text',
                    text: 'Hello, TON!',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Modify message
            (signedData.payload as SignDataPayloadText).text = 'Hacked message';

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });

        it('should fail verification with modified domain', () => {
            const signedData = signData({
                payload: {
                    type: 'text',
                    text: 'Hello, TON!',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Modify domain
            signedData.domain = 'hacked.com';

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });
    });

    describe('binary payload', () => {
        it('should sign and verify binary message', () => {
            const signedData = signData({
                payload: {
                    type: 'binary',
                    bytes: Buffer.from('Hello, TON!').toString('base64'),
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(true);
        });

        it('should fail verification with modified binary data', () => {
            const signedData = signData({
                payload: {
                    type: 'binary',
                    bytes: Buffer.from('Hello, TON!').toString('base64'),
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Modify binary data
            signedData.payload = {
                type: 'binary',
                bytes: Buffer.from('Hacked!').toString('base64'),
            };

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });
    });

    describe('cell payload', () => {
        const createTestCell = (text: string) => {
            return beginCell()
                .storeUint(0, 32) // op = 0
                .storeStringTail(text)
                .endCell()
                .toBoc()
                .toString('base64');
        };

        it('should sign and verify cell message', () => {
            const signedData = signData({
                payload: {
                    type: 'cell',
                    schema: 'message#_ text:string = Message;',
                    cell: createTestCell('Hello, TON!'),
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(true);
        });

        it('should fail verification with modified cell data', () => {
            const signedData = signData({
                payload: {
                    type: 'cell',
                    schema: 'message#_ text:string = Message;',
                    cell: createTestCell('Hello, TON!'),
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Modify cell data
            signedData.payload = {
                type: 'cell',
                schema: 'message#_ text:string = Message;',
                cell: createTestCell('Hacked!'),
            };

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });

        it('should fail verification with modified schema', () => {
            const signedData = signData({
                payload: {
                    type: 'cell',
                    schema: 'message#_ text:string = Message;',
                    cell: createTestCell('Hello, TON!'),
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            // Modify schema
            (signedData.payload as SignDataPayloadCell).schema = 'hacked#_ text:string = Hacked;';

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });
    });
}); 