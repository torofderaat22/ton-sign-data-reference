import { describe, it, expect, beforeAll } from 'vitest';
import { mnemonicToPrivateKey } from '@ton/crypto';
import { signData } from '../sign';
import { verifySignData } from '../verify';
import {
    SignDataPayloadText,
    SignDataPayloadCell,
    SignDataPayloadBinary,
} from '../types';
import { beginCell } from '@ton/core';

describe('sign-data', () => {
    const TEST_MNEMONIC = [
        'unfold',
        'item',
        'school',
        'little',
        'upper',
        'surge',
        'pride',
        'endorse',
        'outer',
        'filter',
        'biology',
        'prefer',
        'regular',
        'island',
        'hidden',
        'dice',
        'nuclear',
        'grace',
        'motor',
        'entire',
        'weird',
        'between',
        'falcon',
        'dwarf',
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

        it('should produce consistent signature structure for text payload', () => {
            const signedData = signData({
                payload: {
                    type: 'text',
                    text: 'Hello, TON!',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            expect(signedData.signature).toBeTypeOf('string');
            expect(signedData.signature.length).toBeGreaterThan(0);
            expect(signedData.timestamp).toBeTypeOf('number');
            expect(signedData.domain).toBe(TEST_DOMAIN);
            expect(signedData.payload).toEqual({
                type: 'text',
                text: 'Hello, TON!',
            });
            expect(signedData.address).toBe(TEST_ADDRESS);
        });

        it('should produce deterministic signatures for same input with mocked timestamp', () => {
            const fixedTime = 1703980800000;
            const originalDateNow = Date.now;
            Date.now = () => fixedTime;

            const signedData1 = signData({
                payload: {
                    type: 'text',
                    text: 'Test message',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const signedData2 = signData({
                payload: {
                    type: 'text',
                    text: 'Test message',
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            Date.now = originalDateNow;

            expect(signedData1.signature).toBe(signedData2.signature);
            expect(signedData1.timestamp).toBe(signedData2.timestamp);
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

        it('should produce consistent signature structure for binary payload', () => {
            const testBytes = Buffer.from('Hello, TON!').toString('base64');

            const signedData = signData({
                payload: {
                    type: 'binary',
                    bytes: testBytes,
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            expect(signedData.signature).toBeTypeOf('string');
            expect(signedData.signature.length).toBeGreaterThan(0);
            expect(signedData.timestamp).toBeTypeOf('number');
            expect(signedData.payload.type).toBe('binary');
            expect((signedData.payload as SignDataPayloadBinary).bytes).toBe(
                testBytes
            );
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

        it('should produce consistent signature structure for cell payload', () => {
            const testCell = createTestCell('Hello, TON!');
            const testSchema = 'message#_ text:string = Message;';

            const signedData = signData({
                payload: {
                    type: 'cell',
                    schema: testSchema,
                    cell: testCell,
                },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            expect(signedData.signature).toBeTypeOf('string');
            expect(signedData.signature.length).toBeGreaterThan(0);
            expect(signedData.timestamp).toBeTypeOf('number');
            expect(signedData.payload.type).toBe('cell');
            expect((signedData.payload as SignDataPayloadCell).schema).toBe(
                testSchema
            );
            expect((signedData.payload as SignDataPayloadCell).cell).toBe(
                testCell
            );
        });

        it('should produce different signatures for different schemas', () => {
            const testCell = createTestCell('Hello, TON!');

            const fixedTime = 1703980800000;
            const originalDateNow = Date.now;
            Date.now = () => fixedTime;

            try {
                const signedData1 = signData({
                    payload: {
                        type: 'cell',
                        schema: 'message#_ text:string = Message;',
                        cell: testCell,
                    },
                    domain: TEST_DOMAIN,
                    privateKey: keyPair.secretKey,
                    address: TEST_ADDRESS,
                });

                const signedData2 = signData({
                    payload: {
                        type: 'cell',
                        schema: 'different#_ text:string = Different;',
                        cell: testCell,
                    },
                    domain: TEST_DOMAIN,
                    privateKey: keyPair.secretKey,
                    address: TEST_ADDRESS,
                });

                expect(signedData1.signature).not.toBe(signedData2.signature);
            } finally {
                Date.now = originalDateNow;
            }
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
            (signedData.payload as SignDataPayloadCell).schema =
                'hacked#_ text:string = Hacked;';

            const isValid = verifySignData({
                signedData,
                publicKey: keyPair.publicKey,
            });

            expect(isValid).toBe(false);
        });
    });

    describe('signature consistency', () => {
        it('should produce different signatures for different domains', () => {
            const fixedTime = 1703980800000;
            const originalDateNow = Date.now;
            Date.now = () => fixedTime;

            const signedData1 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: 'example.com',
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const signedData2 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: 'different.com',
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            Date.now = originalDateNow;
            expect(signedData1.signature).not.toBe(signedData2.signature);
        });

        it('should produce different signatures for different addresses', () => {
            const fixedTime = 1703980800000;
            const originalDateNow = Date.now;
            Date.now = () => fixedTime;

            const signedData1 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const signedData2 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: 'UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJKZ',
            });

            Date.now = originalDateNow;

            expect(signedData1.signature).not.toBe(signedData2.signature);
        });

        it('should produce different signatures for different timestamps', () => {
            let mockTime = 1703980800000;
            const originalDateNow = Date.now;

            Date.now = () => {
                const currentTime = mockTime;
                mockTime += 2000;
                return currentTime;
            };

            const signedData1 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            const signedData2 = signData({
                payload: { type: 'text', text: 'Test' },
                domain: TEST_DOMAIN,
                privateKey: keyPair.secretKey,
                address: TEST_ADDRESS,
            });

            Date.now = originalDateNow;

            expect(signedData1.timestamp).not.toBe(signedData2.timestamp);
            expect(signedData1.signature).not.toBe(signedData2.signature);
            expect(signedData2.timestamp - signedData1.timestamp).toBe(2);
        });
    });

    describe('regression tests with known signatures', () => {
        it('should maintain backward compatibility with known signatures', () => {
            const fixedTime = 1703980800000;
            const originalDateNow = Date.now;
            Date.now = () => fixedTime;

            const testCases = [
                {
                    name: 'text payload',
                    payload: { type: 'text' as const, text: 'Hello, TON!' },
                    expectedSignature:
                        '/34cktAUdWpCVgUfyXQlFtINRhdC9DRlshhMtOx1I9G2TDLV20xrHPxp9fvifz3EHZthCnSHN/IVF8zw7twNCw==',
                },
                {
                    name: 'binary payload',
                    payload: {
                        type: 'binary' as const,
                        bytes: Buffer.from('Hello, TON!').toString('base64'),
                    },
                    expectedSignature:
                        'R7vQ6Zj2CYXJAa+ldLWgwPbJyR/58XrQV3HDw4yuqSYmR8PcoBpt5h1DOLX0LgxjOE3tieuwsDP6WwnCDkAECg==',
                },
                {
                    name: 'cell payload',
                    payload: {
                        type: 'cell' as const,
                        schema: 'message#_ text:string = Message;',
                        cell: beginCell()
                            .storeUint(0, 32)
                            .storeStringTail('Hello, TON!')
                            .endCell()
                            .toBoc()
                            .toString('base64'),
                    },
                    expectedSignature:
                        'xULn8inA8A1qhFEFK8jpY+UEq7dHlpA/tm8LkxBBzRkZjTrni31H1p5Q+XMTS4I7HWsyC0i82teVdwc02lg4AQ==',
                },
            ];

            testCases.forEach(({ name, payload, expectedSignature }) => {
                const signedData = signData({
                    payload,
                    domain: TEST_DOMAIN,
                    privateKey: keyPair.secretKey,
                    address: TEST_ADDRESS,
                });

                expect(signedData.signature, `${name} signature mismatch`).toBe(
                    expectedSignature
                );

                const isValid = verifySignData({
                    signedData,
                    publicKey: keyPair.publicKey,
                });

                expect(isValid, `${name} verification failed`).toBe(true);
            });

            Date.now = originalDateNow;
        });
    });
});
