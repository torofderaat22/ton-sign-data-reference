import { describe, it, expect } from 'vitest';
import { encodeDnsName } from '../utils';

const buf = (s: string) => Buffer.from(s, 'utf8');

describe('encodeDnsName', () => {
    describe('valid domains', () => {
        it('should encode "tonkeeper.com" as "com\\tonkeeper\\0"', () => {
            const encoded = encodeDnsName('tonkeeper.com');
            expect(encoded.equals(buf('com\0tonkeeper\0'))).toBe(true);
            expect(encoded.length).toBe(14); // 3 + 1 + 9 + 1
        });

        it('should encode "ton-connect.github.io" as "io\\0github\\0ton-connect\\0"', () => {
            const encoded = encodeDnsName('ton-connect.github.io');
            expect(encoded.equals(buf('io\0github\0ton-connect\0'))).toBe(true);
            expect(encoded.length).toBe(22);
        });

        it('should normalize mixed-case "tONkEEpEr.CoM" to lowercase', () => {
            const encoded = encodeDnsName('tONkEEpEr.CoM');
            expect(encoded.equals(buf('com\0tonkeeper\0'))).toBe(true);
        });

        it('should handle trailing dot in "tonkeeper.com."', () => {
            const encoded = encodeDnsName('tonkeeper.com.');
            expect(encoded.equals(buf('com\0tonkeeper\0'))).toBe(true);
        });

        it('should encode single-label "tonkeeper" as "tonkeeper\\0"', () => {
            const encoded = encodeDnsName('tonkeeper');
            expect(encoded.equals(buf('tonkeeper\0'))).toBe(true);
            expect(encoded.length).toBe(10);
        });

        it('should encode "tonkeeper." as single-label', () => {
            const encoded = encodeDnsName('tonkeeper.');
            expect(encoded.equals(buf('tonkeeper\0'))).toBe(true);
          });

        it('should encode the root domain "." as a single null byte', () => {
            const encoded = encodeDnsName('.');
            expect(encoded.equals(Buffer.from([0]))).toBe(true);
            expect(encoded.length).toBe(1);
        });

    });

    describe('internationalized domain names (IDN)', () => {
        it('should encode Cyrillic "пример.com" as "com\\0xn--e1afmkfd\\0"', () => {
            const encoded = encodeDnsName('пример.com');
            expect(encoded.equals(buf('com\0xn--e1afmkfd\0'))).toBe(true);
        });

        it('should encode "example.中国" (Chinese TLD) as "xn--fiqs8s\\0example\\0"', () => {
            const encoded = encodeDnsName('example.中国');
            expect(encoded.equals(buf('xn--fiqs8s\0example\0'))).toBe(true);
        });

        it('should encode single-label Arabic "اختبار" as "xn--mgbachtv\\0"', () => {
            const encoded = encodeDnsName('اختبار');
            expect(encoded.equals(buf('xn--mgbachtv\0'))).toBe(true);
        });
    });

    describe('boundary conditions', () => {
        it('should allow a 63-byte label', () => {
            const domain = `${'a'.repeat(63)}.com`;
            const encoded = encodeDnsName(domain);
            expect(encoded.equals(buf(`com\0${'a'.repeat(63)}\0`))).toBe(true);
            expect(encoded.length).toBe(68); // 3 + 1 + 63 + 1
        });

        it('should reject a 64-byte label', () => {
            const domain = `${'a'.repeat(64)}.com`;
            expect(() => encodeDnsName(domain)).toThrow(/invalid label/i);
        });

        it('should allow a total encoded length of exactly 126 bytes', () => {
            const domain = `${'a'.repeat(63)}.${'b'.repeat(57)}.com`;
            const encoded = encodeDnsName(domain);
            expect(encoded.length).toBe(126); // upper bound in TEP-81

            const prefix = buf('com\0');
            expect(encoded.subarray(0, prefix.length).equals(prefix)).toBe(
                true
            );
            expect(encoded[encoded.length - 1]).toBe(0); // ends with null byte
        });

        it('should reject encoded length greater than 126 bytes', () => {
            const domain = `${'a'.repeat(63)}.${'b'.repeat(58)}.com`;
            expect(() => encodeDnsName(domain)).toThrow(
                /Encoded name is 127 bytes/i
            );
        });
    });

    describe('invalid inputs', () => {
        it('should reject an empty string', () => {
            expect(() => encodeDnsName('')).toThrow(/non[- ]?empty/i);
        });

        it('should reject a domain with an empty label ("bad..com")', () => {
            expect(() => encodeDnsName('bad..com')).toThrow(/empty label/i);
        });

        it('should reject a label containing space ("bad domain.com")', () => {
            expect(() => encodeDnsName('bad domain.com')).toThrow(
                /invalid label/i
            );
        });

        it('should reject a label containing control character ("bad\\u0007bell.com")', () => {
            const domain = 'bad\u0007bell.com';
            expect(() => encodeDnsName(domain)).toThrow(/invalid label/i);
        });

        it('should reject a domain starting with a dot (".com")', () => {
            expect(() => encodeDnsName('.com')).toThrow(/empty label/i);
        });

        it('should reject domains with leading/trailing spaces', () => {
            expect(() => encodeDnsName('  example.com  ')).toThrow(
                /invalid label|0x20/i
            );
        });
    });
});
