import { Address } from '@ton/core';
import nacl from 'tweetnacl';
import { SignDataResult } from './types';
import { createTextBinaryHash, createCellHash } from './utils';

export interface VerifyParams {
    signedData: SignDataResult;
    publicKey: Buffer;
}

/**
 * Verifies sign-data signature.
 *
 * Supports three payload types:
 * 1. text - for text messages
 * 2. binary - for arbitrary binary data
 * 3. cell - for TON Cell with TL-B schema
 *
 * @param params Verification parameters
 * @returns true if signature is valid
 */
export function verifySignData(params: VerifyParams): boolean {
    const { signedData, publicKey } = params;
    const { signature, address, timestamp, domain, payload } = signedData;
    const parsedAddr = Address.parse(address);

    // Create hash based on payload type
    const finalHash =
        payload.type === 'cell'
            ? createCellHash(payload, parsedAddr, domain, timestamp)
            : createTextBinaryHash(payload, parsedAddr, domain, timestamp);

    // Verify Ed25519 signature
    return nacl.sign.detached.verify(
        new Uint8Array(finalHash),
        new Uint8Array(Buffer.from(signature, 'base64')),
        new Uint8Array(publicKey)
    );
}
