import { Address } from '@ton/core';
import nacl from 'tweetnacl';
import { SignDataParams, SignDataResult } from './types';
import { createTextBinaryHash, createCellHash } from './utils';

/**
 * Signs data according to TON Connect sign-data protocol.
 *
 * Supports three payload types:
 * 1. text - for text messages
 * 2. binary - for arbitrary binary data
 * 3. cell - for TON Cell with TL-B schema
 *
 * @param params Signing parameters
 * @returns Signed data with base64 signature
 */
export function signData(params: SignDataParams): SignDataResult {
    const { payload, domain, privateKey, address } = params;
    const timestamp = Math.floor(Date.now() / 1000);
    const parsedAddr = Address.parse(address);

    // Create hash based on payload type
    const finalHash =
        payload.type === 'cell'
            ? createCellHash(payload, parsedAddr, domain, timestamp)
            : createTextBinaryHash(payload, parsedAddr, domain, timestamp);

    // Sign with Ed25519
    const signature = nacl.sign.detached(
        new Uint8Array(finalHash),
        new Uint8Array(privateKey)
    );

    return {
        signature: Buffer.from(signature).toString('base64'),
        address,
        timestamp,
        domain,
        payload,
    };
}
