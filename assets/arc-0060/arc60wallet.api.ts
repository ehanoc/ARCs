import {
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_hash_sha512,
    crypto_scalarmult_ed25519_base_noclamp,
    ready
} from 'libsodium-wrappers-sumo'

import * as crypto from 'crypto'
import { readFileSync } from 'fs';
import path from 'path';
import Ajv, { JSONSchemaType } from 'ajv';
import sha512, { sha512_256 } from 'js-sha512'
import axios, { AxiosResponse } from 'axios'
import * as util from 'util'

export interface HDWalletMetadata {
    /**
    * HD Wallet purpose value. First derivation path level. 
    * Hardened derivation is used.
    */
    purpose: number,

    /**
    * HD Wallet coin type value. Second derivation path level.
    * Hardened derivation is used.
    */
    coinType: number,

    /**
    * HD Wallet account number. Third derivation path level.
    * Hardened derivation is used.
    */
    account: number,

    /**
    * HD Wallet change value. Fourth derivation path level.
    * Soft derivation is used.
    */
    change: number,

    /**
    * HD Wallet address index value. Fifth derivation path level.
    * Soft derivation is used.
    */
    addrIdx: number,
}

// StdSigData type
export interface StdSigData {
    data: string;
    signer: Uint8Array;
    hdPath?: HDWalletMetadata
}

// ScopeType type
export enum ScopeType {
    UNKNOWN = -1,
    CHALLENGE32 = 0,
    MX_RANDOM = 1,
    JSON = 2,
    LSIG_TEMPLATE = 3
}

// StdSignMetadata type
export interface StdSignMetadata {
    scope: ScopeType;
    encoding: string;
}

// StdSignature type 64 bytes array
export type StdSignature = Uint8Array;

export class SignDataError extends Error {
    constructor(public readonly code: number, message: string, data?: any) {
        super(message);
    }
}

// Error Codes & Messages
export const ERROR_INVALID_SCOPE: SignDataError = new SignDataError(4600, 'Invalid Scope');
export const ERROR_DOESNT_MATCH_SCHEMA: SignDataError = new SignDataError(4601, 'Doesn\'t match schema');
export const ERROR_FAILED_DECODING: SignDataError = new SignDataError(4602, 'Failed decoding');
export const ERROR_INVALID_SIGNER: SignDataError = new SignDataError(4603, 'Invalid Signer');
export const ERROR_INVALID_HD_PATH: SignDataError = new SignDataError(4604, 'Invalid HD Path');
export const ERROR_UNKNOWN: SignDataError = new SignDataError(4605, 'Unknown Error');
export const ERROR_UNKNOWN_LSIG: SignDataError = new SignDataError(4606, 'Unknown LSIG');

export class Arc60WalletApi {

    /**
     * Known LSIG template hashes. 
     */
    static known_lsigs_template_hashes: string[] = [
        "501bfa4c62e5282b447ae0b35ed1ba24544a74bfee948701744bbc46d8a36464"
    ]

    /**
     * Constructor for Arc60WalletApi
     * 
     * @param k - is the seed value as part of Ed25519 key generation.
     * 
     * The following link has a visual explanation of the key gen and signing process: 
     * 
     * https://private-user-images.githubusercontent.com/1436105/316953159-aba6b82f-b558-41b9-abcb-57f682026f96.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MTU4Mzk0MjMsIm5iZiI6MTcxNTgzOTEyMywicGF0aCI6Ii8xNDM2MTA1LzMxNjk1MzE1OS1hYmE2YjgyZi1iNTU4LTQxYjktYWJjYi01N2Y2ODIwMjZmOTYucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI0MDUxNiUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNDA1MTZUMDU1ODQzWiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9NjE3NGUxMDkzMzkxY2RkMzU3OTVhOWY0MzJkNzBmOGJhN2JlNDY4OTQzYzBjY2QwNzEyOTg1NzcwNDAzM2EzMSZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QmYWN0b3JfaWQ9MCZrZXlfaWQ9MCZyZXBvX2lkPTAifQ.YBMeEI0SRaxjeRRZRiZi0_58wEeCk0hgl5gIyPXluas
     * 
     */
    constructor(private readonly k: Uint8Array) {
        this.k = k;
    }

    /**
     * Arbitrary data signing function. 
     * Based on the provided scope and encoding, it decodes the data and signs it.
     * 
     * 
     * @param signingData - includes the data to be signed and the signer's public key
     * @param metadata - includes the scope and encoding of the data
     * @returns - signature of the data from the signer.
     * 
     * @throws - Error 4600 - Invalid Scope - if the scope is not supported
     * @throws - Error 4601 - DOesn't match schema - The data doesn't match the schema for the scope
     * @throws - Error 4602 - Failed decoding - if the data can't be decoded
     * @throws - Error 4603 - Invalid Signer - if the signer is not a valid public key
     * @throws - Error 4604 - Invalid HD Path - if the HD path is invalid
     */
    async signData(signingData: StdSigData, metadata: StdSignMetadata): Promise<StdSignature> {
        // decode signing data with chosen metadata.encoding
        let decodedData: Uint8Array
        let toSign: Uint8Array

        // decode data
        switch(metadata.encoding) {
            case 'base64':
                decodedData = Buffer.from(signingData.data, 'base64');
                break;
            case 'hex':
                decodedData = Buffer.from(signingData.data, 'hex');
                break;
            default:
                throw ERROR_FAILED_DECODING;
        }

        // Reject if Program bytes prefix is present in byte array
        if(decodedData.slice(0, 7).toString() === "Program") {
            throw ERROR_DOESNT_MATCH_SCHEMA;
        }
        
        // validate against schema
        switch(metadata.scope) {
            case ScopeType.CHALLENGE32:
                if(decodedData.length !== 32) {
                    throw ERROR_DOESNT_MATCH_SCHEMA;
                }

                toSign = decodedData;
                break;
            case ScopeType.MX_RANDOM:
                // Check MX prefix
                if(decodedData[0] !== 0x6D || decodedData[1] !== 0x78) {
                    throw ERROR_DOESNT_MATCH_SCHEMA;
                }

                toSign = decodedData
                break;
            case ScopeType.LSIG_TEMPLATE:
                // LSIG schema validation
                // Wallets should load the LSIG Schema from their local storage at run-time. 
                const file_contents = readFileSync(path.resolve(__dirname, 'lsig-template-request.json'), 'utf8');

                const lsigSchema: JSONSchemaType<any> = JSON.parse(file_contents)
                
                const ajv = new Ajv();
                const validate = ajv.compile(lsigSchema);

                const lsigData = JSON.parse(decodedData.toString());

                if(!validate(lsigData)) {
                    // log error
                    console.log("logging err")
                    console.log(validate.errors);
                    throw ERROR_DOESNT_MATCH_SCHEMA;
                }

                // hash lsig template request by excluding values
                const lSigRequestNoValues = {
                    LogicSignatureDescription: {
                        ...lsigData.LogicSignatureDescription,
                        values: undefined
                    },
                    program: lsigData.program,
                    hash: lsigData.hash
                }

                // hash lsig template request by excluding values
                const hashTemplate: string = sha512_256.update(JSON.stringify(lSigRequestNoValues)).hex()

                // check if hash is one of the known hashes
                if(!Arc60WalletApi.known_lsigs_template_hashes.includes(hashTemplate)) {
                    throw ERROR_UNKNOWN_LSIG;
                }

                // replaces values
                let finalTeal = atob(lsigData.program)

                // get values
                const values = lsigData.LogicSignatureDescription.values
    
                // get keys
                const keys = Object.keys(values)
                
                // loop through keys
                for (const key of keys) {
                    finalTeal = finalTeal.replaceAll(key, values[key as keyof typeof values].toString())
                }
                
                // No standalone compiler :(
                // Submit to node to compile 
                const result: AxiosResponse = await axios.post('https://testnet-api.algonode.cloud:443/v2/teal/compile',
                    Buffer.from(finalTeal), {
                    headers: {
                        "Content-Type": "application/x-binary",
                        "X-Algo-API-Token": "a".repeat(64)
                    }
                })

                const compiled: Buffer = Buffer.from(result.data.result, 'base64')

                // concat with tag
                toSign = new Uint8Array(Buffer.concat([Buffer.from("Program"), compiled]))
                break;
            default:
                throw ERROR_INVALID_SCOPE;
        }

        // perform signature using libsodium
        return await this.rawSign(this.k, toSign);
    }

    /**
     * Raw Signing function called by signData and signTransaction
     *
     * Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6
     *
     * Edwards-Curve Digital Signature Algorithm (EdDSA)
     *
     * @param k - seed value for Ed25519 key generation
     * @param data
     * - data to be signed in raw bytes
     *
     * @returns
     * - signature holding R and S, totally 64 bytes
     */
    private async rawSign(k: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
        await ready // libsodium

        // SHA512 hash of the seed value using nodejs crypto
        const raw: Uint8Array = new Uint8Array(crypto.createHash('sha512')
            .update(k)
            .digest())

        const scalar: Uint8Array = raw.slice(0, 32);
        const rH: Uint8Array = raw.slice(32, 64);

        // clamp scalar
        //Set the bits in kL as follows:
        // little Endianess
        scalar[0] &= 0b11_11_10_00; // the lowest 3 bits of the first byte of kL are cleared
        scalar[31] &= 0b01_11_11_11; // the highest bit of the last byte is cleared
        scalar[31] |= 0b01_00_00_00; // the second highest bit of the last byte is set

        // \(1): pubKey = scalar * G (base point, no clamp)
        const publicKey = crypto_scalarmult_ed25519_base_noclamp(scalar);

        // \(2): h = hash(c || msg) mod q
        const r = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(Buffer.concat([rH, data])))

        // \(4):  R = r * G (base point, no clamp)
        const R = crypto_scalarmult_ed25519_base_noclamp(r)

        // h = hash(R || pubKey || msg) mod q
        let h = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(Buffer.concat([R, publicKey, data])));

        // \(5): S = (r + h * k) mod q
        const S = crypto_core_ed25519_scalar_add(r, crypto_core_ed25519_scalar_mul(h, scalar))

        return new Uint8Array(Buffer.concat([R, S]))
    }

    /**
     * 
     * @param k - seed
     * @returns - public key
     */
    static async getPublicKey(k: Uint8Array): Promise<Uint8Array> {
        await ready // libsodium

        // SHA512 hash of the seed value using nodejs crypto
        const raw: Uint8Array = new Uint8Array(crypto.createHash('sha512')
            .update(k)
            .digest())

        const scalar: Uint8Array = raw.slice(0, 32);

        // clamp scalar
        //Set the bits in kL as follows:
        // little Endianess
        scalar[0] &= 0b11_11_10_00; // the lowest 3 bits of the first byte of kL are cleared
        scalar[31] &= 0b01_11_11_11; // the highest bit of the last byte is cleared
        scalar[31] |= 0b01_00_00_00; // the second highest bit of the last byte is set

        // \(1): pubKey = scalar * G (base point, no clamp)
        return crypto_scalarmult_ed25519_base_noclamp(scalar);
    }
}