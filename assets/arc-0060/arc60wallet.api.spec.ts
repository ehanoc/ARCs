import { randomBytes } from "crypto"
import { ARC31AuthRequest, ARC47LsigTemplateRequest, Arc60WalletApi, ERROR_DOESNT_MATCH_SCHEMA, ERROR_FAILED_DECODING, ERROR_INVALID_SCOPE, ERROR_INVALID_SIGNER, ERROR_UNKNOWN_LSIG, ScopeType, StdSigData } from "./arc60wallet.api"
import { crypto_sign_verify_detached, ready } from "libsodium-wrappers-sumo"
import * as msgpack from "algo-msgpack-with-bigint"

jest.setTimeout(20000)

describe('ARC60 TEST SUITE', () => {

    let arc60wallet: Arc60WalletApi
    let seed: Uint8Array

    beforeEach(() => {
        seed = new Uint8Array(Buffer.from("b12e7cb8127d8fd07b03893f1aaa743bb737cff749ebac7f9af62b376f4494cc", 'hex'))
        arc60wallet = new Arc60WalletApi(seed);
    })

    // describe group for rawSign
    describe('rawSign', () => {
        it('(OK) should sign data correctly', async () => {
            const data = new Uint8Array(32).fill(2);
            const rawSign = (arc60wallet as any).rawSign.bind(arc60wallet);
            const signature = await rawSign(seed, data);

            expect(signature).toBeInstanceOf(Uint8Array);
            expect(signature.length).toBe(64); // Ed25519 signature length
        });

        it('(FAILS) should throw error for shorter incorrect length seed', async () => {
            const data = new Uint8Array(32).fill(2);
            const badSeed = new Uint8Array(31); // Incorrect shorter length seed
            const rawSign = (arc60wallet as any).rawSign.bind(arc60wallet);

            try {
                await rawSign(badSeed, data);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
        it('(FAILS) should throw error for longer incorrect length seed', async () => {
            const data = new Uint8Array(32).fill(2);
            const badSeed = new Uint8Array(33); // Incorrect longer length seed
            const rawSign = (arc60wallet as any).rawSign.bind(arc60wallet);

            try {
                await rawSign(badSeed, data);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
    });

    // describe group for getPublicKey
    describe('getPublicKey', () => {
        it('(OK) should return the correct public key', async () => {
            const publicKey = await Arc60WalletApi.getPublicKey(seed);

            expect(publicKey).toBeInstanceOf(Uint8Array);
            expect(publicKey.length).toBe(32); // Ed25519 public key length
        });

        it('(FAILS) should throw error for shorter incorrect length seed', async () => {
            const badSeed = new Uint8Array(31); // Incorrect length seed

            try {
                await Arc60WalletApi.getPublicKey(badSeed);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
        it('(FAILS) should throw error for longer incorrect length seed', async () => {
            const badSeed = new Uint8Array(33); // Incorrect length seed

            try {
                await Arc60WalletApi.getPublicKey(badSeed);
            } catch (error) {
                expect(error).toBeDefined();
            }
        });
    });


    // Reject any scope if "Program" is part of payload
    describe('Reject unknown LSIGs', () => {
        it('\(FAILS) Tries to sign with any scope if "Program" is present', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(32))
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.concat([Buffer.from("Program"), challenge]).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'base64' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })
    })

    // describe group for CHALLENGE32
    describe('SCOPE == CHALLENGE32', () => {
        it('\(OK) Signs random 32 byte challenge', async () => {
            const challenge: Uint8Array = new Uint8Array(Buffer.from("a77ae7c548baaa5ebc4c1dee700c7032e361b58788e3cbbd3ec75d0754825918", 'hex'))
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: publicKey
            }

            const signature: Uint8Array = await arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'base64' })
            expect(signature).toBeDefined()

            // verify signature 
            await ready //libsodium
            expect(crypto_sign_verify_detached(signature, challenge, publicKey)).toBeTruthy()

        })

        it('\(FAILS) Tries to sign with bad size longer random data as CHALLENGE32', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(33)) // BAD SIZE! SHOULD FAIL
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'base64' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })
        it('\(FAILS) Tries to sign with bad size shorter random data as CHALLENGE32', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(31)) // BAD SIZE! SHOULD FAIL
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'base64' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })
    })

    // describe group for MX_RANDOM
    describe('SCOPE == MX_RANDOM', () => {
        it('\(OK) Signs random 32 byte challenge with MX prefix', async () => {
            // random data with MX prefix
            const mxValue: Uint8Array = new Uint8Array([0x6d, 0x78])
            const mxRandomData: Buffer = Buffer.concat([mxValue, new Uint8Array(randomBytes(30))])


            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: mxRandomData.toString('base64'),
                signer: publicKey
            }

            const signature: Uint8Array = await arc60wallet.signData(signData, { scope: ScopeType.MX_RANDOM, encoding: 'base64' })
            expect(signature).toBeDefined()

            // verify signature 
            await ready //libsodium
            expect(crypto_sign_verify_detached(signature, mxRandomData, publicKey)).toBeTruthy()
        })

        it('\(OK) Signs 512 bytes random data with MX prefix', async () => {
            // random data with MX prefix
            const mxValue: Uint8Array = new Uint8Array([0x6d, 0x78])
            const mxRandomData: Buffer = Buffer.concat([mxValue, new Uint8Array(randomBytes(512))])

            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: mxRandomData.toString('base64'),
                signer: publicKey
            }

            const signature: Uint8Array = await arc60wallet.signData(signData, { scope: ScopeType.MX_RANDOM, encoding: 'base64' })
            expect(signature).toBeDefined()

            // verify signature 
            await ready //libsodium
            expect(crypto_sign_verify_detached(signature, mxRandomData, publicKey)).toBeTruthy()
        })

        it('\(FAILS) Tries to sign but no MX prefix is present', async () => {
            const mxRandomData: Buffer = randomBytes(66)
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: mxRandomData.toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.MX_RANDOM, encoding: 'base64' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })
    })

    // describe bad scope
    describe('SCOPE == INVALID', () => {
        it('\(FAILS) Tries to sign with invalid scope', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(32))
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: publicKey
            }

            // bad scope
            expect(arc60wallet.signData(signData, { scope: ScopeType.UNKNOWN, encoding: 'base64' })).rejects.toThrow(ERROR_INVALID_SCOPE)
        })
    })

    // describe group for LSIG
    describe('SCOPE == LSIG_TEMPLATE', () => {
        it('\(FAIL) Fails to sign LSIG_TEMPLATE program, templated program does not match known hashes', async () => {
            const lSigRequest: ARC47LsigTemplateRequest = {
                LogicSignatureDescription: {
                    name: "Sample LSig",
                    description: "This a sample description",
                    variables: [
                        {
                            name: "Template amount",
                            variable: "TMPL_AMOUNT",
                            type: "number",
                            description: "This is a sample template amount as number"
                        },
                        {
                            name: "Template receiver",
                            variable: "TMPL_RECEIVER",
                            type: "string",
                            description: "This is a sample template receiver as string"
                        }
                    ],
                    program: "badProgram",
                },
                hash: "866b786c4c36c22a9f2aab6bc51bdbfc81d2a645a5a1839f62b76f626f5fc9fe",
                values:
                {
                    TMPL_AMOUNT: 1000000,
                    TMPL_RECEIVER: "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA"
                }
            }

            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(JSON.stringify(lSigRequest)).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.LSIG_TEMPLATE, encoding: 'base64' })).rejects.toThrow(ERROR_UNKNOWN_LSIG)
        })

        it('\(FAIL) Bad LSIG_TEMPLATE request, fails schema validation', async () => {
            const lSigRequest = {}

            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(JSON.stringify(lSigRequest)).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.LSIG_TEMPLATE, encoding: 'base64' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })

        it('\(OK) Signs LSIG_TEMPLATE program, templated program is known, values replaced and signature produced', async () => {
            // ARC47 template + values
            const lSigRequest: ARC47LsigTemplateRequest = {
                LogicSignatureDescription: {
                    name: "Sample LSig",
                    description: "This a sample description",
                    variables: [
                        {
                            name: "Template amount",
                            variable: "TMPL_AMOUNT",
                            type: "number",
                            description: "This is a sample template amount as number"
                        },
                        {
                            name: "Template receiver",
                            variable: "TMPL_RECEIVER",
                            type: "string",
                            description: "This is a sample template receiver as string"
                        }
                    ],
                    program: "I3ByYWdtYSB2ZXJzaW9uIDkKCi8vIFZlcmlmeSB0aGlzIGlzIGEgcGF5bWVudAp0eG4gVHlwZUVudW0KaW50IHBheQo9PQoKLy8gVmVyaWZ5IHRoaXMgaXMgbm90IHJla2V5aW5nIHRoZSBzZW5kZXIgYWRkcmVzcwp0eG4gUmVrZXlUbwpnbG9iYWwgWmVyb0FkZHJlc3MKPT0KYXNzZXJ0CgovLyBWZXJpZnkgdGhlIHNlbmRlcidzIGFjY291bnQgaXMgbm90IGJlaW5nIGNsb3NlZAp0eG4gQ2xvc2VSZW1haW5kZXJUbwpnbG9iYWwgWmVyb0FkZHJlc3MKPT0KYXNzZXJ0CgovLyBWZXJpZnkgdGhlIHJlY2VpdmVyIGlzIGVxdWFsIHRvIHRoZSB0ZW1wbGF0ZWQgcmVjZWl2ZXIgYWRkcmVzcwp0eG4gUmVjZWl2ZXIKYWRkciBUTVBMX1JFQ0VJVkVSCj09CmFzc2VydAoKLy8gVmVyaWZ5IHRoZSBhbW91bnQgaXMgZXF1YWwgdG8gdGhlIHRlbXBsYXRlZCBhbW91bnQKdHhuIEFtb3VudAppbnQgVE1QTF9BTU9VTlQKPT0KYXNzZXJ0CgovLyBWZXJpZnkgdGhlIGN1cnJlbnQgcm91bmQgaXMgd2l0aGluIDUwMCByb3VuZHMgb2YgYSBwcm9kdWN0IG9mIDI1XzAwMApnbG9iYWwgUm91bmQKaW50IDI1XzAwMAolCnN0b3JlIDAKCmxvYWQgMAppbnQgNTAwCjw9Cgpsb2FkIDAKaW50IDI0XzUwMAo+PQoKfHwKYXNzZXJ0CgovLyBWZXJpZnkgbGVhc2UgCnR4biBMZWFzZQpieXRlICJzY2hlZHVsZWQgMjVfMDAwIHBheW1lbnQiCnNoYTI1Ngo9PQo="
                },
                hash: "866b786c4c36c22a9f2aab6bc51bdbfc81d2a645a5a1839f62b76f626f5fc9fe",
                values:
                {
                    TMPL_AMOUNT: 1000000,
                    TMPL_RECEIVER: "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA"
                }
            }

            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(JSON.stringify(lSigRequest)).toString('base64'),
                signer: publicKey
            }

            const signature: Uint8Array = await arc60wallet.signData(signData, { scope: ScopeType.LSIG_TEMPLATE, encoding: 'base64' })
            // expect signature to be hex
            expect(Buffer.from(signature).toString('hex')).toEqual("15ebdae08194f8d6ab64067be536f8f7538acda23474426a157433d09076f22a9211e956ff7473af40d5392285589be26c370c636e873a570d9316bd4bb74706")
        })
    })

    // ARC31 auth group
    describe('ARC31 AUTH', () => {
        it('(OK) Sign ARC31 message', async () => {
            const arc31Message: ARC31AuthRequest = {
                authAcc: "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA",
                domain: "arc31.io",
                nonce: "1234567890",
                desc: "This is a sample description",
                meta: "This is a sample meta"
            }

            // signData
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(JSON.stringify(arc31Message)).toString('base64'),
                signer: publicKey
            }

            const signature: Uint8Array = await arc60wallet.signData(signData, { scope: ScopeType.ARC31, encoding: 'base64' })
            
            // verify

            // msgpack encode request
            const encoded: Uint8Array = msgpack.encode(arc31Message, { sortKeys: true, ignoreUndefined: true })

            // verify signature 
            await ready //libsodium
            expect(crypto_sign_verify_detached(signature, encoded, publicKey)).toBeTruthy()
        })

        it('(FAILS) Tries to sign ARC31 with bad schema', async () => {
            const arc31Message = {
                authAcc: "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA",
                domain: "arc31.io",
            }

            // signData
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(JSON.stringify(arc31Message)).toString('hex'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.ARC31, encoding: 'hex' })).rejects.toThrow(ERROR_DOESNT_MATCH_SCHEMA)
        })
    })

    // bad signer
    describe('Invalid or Unkown Signer', () => {
        it('(FAILS) Tries to sign with bad signer', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(32))

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: new Uint8Array(31) // Bad signer
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'base64' })).rejects.toThrow(ERROR_INVALID_SIGNER)
        })
    })

    // unkown encoding
    describe('Unknown Encoding', () => {
        it('(FAILS) Tries to sign with unknown encoding', async () => {
            const challenge: Uint8Array = new Uint8Array(randomBytes(32))
            const publicKey: Uint8Array = await Arc60WalletApi.getPublicKey(seed)

            const signData: StdSigData = {
                data: Buffer.from(challenge).toString('base64'),
                signer: publicKey
            }

            expect(arc60wallet.signData(signData, { scope: ScopeType.CHALLENGE32, encoding: 'unknown' })).rejects.toThrow(ERROR_FAILED_DECODING)
        })
    })
})