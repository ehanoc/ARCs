import { CryptoKX, KeyPair, crypto_kx_client_session_keys, crypto_kx_server_session_keys, crypto_scalarmult, crypto_secretbox_NONCEBYTES, crypto_secretbox_easy, crypto_secretbox_open_easy, crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519, crypto_sign_keypair, ready, to_base64 } from "libsodium-wrappers-sumo"
import * as bip39 from "bip39"
import { randomBytes } from "crypto"
import { ContextualCryptoApi, ERROR_BAD_DATA, Encoding, KeyContext, SignMetadata } from "./contextual.api.crypto"
import * as msgpack from "algo-msgpack-with-bigint"

describe("Contextual Derivation & Signing", () => {

    let cryptoService: ContextualCryptoApi
    let bip39Mnemonic: string = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
    let seed: Buffer

    beforeAll(() => {
        seed = bip39.mnemonicToSeedSync(bip39Mnemonic, "")
    })
    
	beforeEach(() => {
        cryptoService = new ContextualCryptoApi(seed)
    })

	afterEach(() => {})

    describe("\(Derivations) Context", () => {
            describe("Addresses", () => {
                describe("Soft Derivations", () => {
                    it("\(OK) Derive m'/44'/283'/0'/0/0 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("7915e7ecbaad1dc9bc22a9e496686687f1a8cb4895b7ca46f86d64dd56c6cd97", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/283'/0'/0/1 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 1)
                        expect(key).toEqual(new Uint8Array(Buffer.from("054a6881d8809c348a402d67ba2feedcd8e3145f40f21a6bbd0de09c30c78d0a", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/283'/0'/0/2 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 2)
                        expect(key).toEqual(new Uint8Array(Buffer.from("8cea8052cfa1fd8cec0b4fad6241a91f2edbfe9f072586f243839174e40a25ef", "hex")))
                    })

                    it("\(OK) Derive m'/44'/283'/3'/0/0 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 3, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("cf8d28a3d41bc656acbfeadb64d06054142c97bee6a987c11d934f84853df866", "hex")))
                    })
                })

                describe("Hard Derivations", () => {
                    it("\(OK) Derive m'/44'/283'/1'/0/0 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 1, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("04f3ba279aa781ab4f8f79aaf6cf91e3d7ff75429064dc757001a30e10c628df", "hex")))
                    })
        
                    it("\(OK) Derive m'/44'/283'/2'/0/1 Algorand Address Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 2, 1)
                        expect(key).toEqual(new Uint8Array(Buffer.from("400d78302258dc7b3cb56d1a09f85b018e8100865ced0b5cda474c26bbc07c30", "hex")))
                    })
                })
            })

            describe("Identities", () => {
                describe("Soft Derivations", () => {
                    it("\(OK) Derive m'/44'/0'/0'/0/0 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("28804f08d8c145e172c998fe75058237b8181846ca763894ae3eefea6ab88352", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/0'/0'/0/1 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 1)
                        expect(key).toEqual(new Uint8Array(Buffer.from("fc8d1c79edd406fa415cb0a76435eb83b6f8af72cd9bd673753471470205057a", "hex")))
                    })
            
                    it("\(OK) Derive m'/44'/0'/0'/0/2 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 2)
                        expect(key).toEqual(new Uint8Array(Buffer.from("f7e317899420454886fe79f24e25af0bbb1856c440b14829674015e5fc2ad28a", "hex")))
                    })
                })

                describe("Hard Derivations", () => {
                    it("\(OK) Derive m'/44'/0'/1'/0/0 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 1, 0)
                        expect(key).toEqual(new Uint8Array(Buffer.from("dddea98ec1fd24f9045ef0cade9055116079c87d16e51a0a081e94a8fb905435", "hex")))
                    })
        
                    it("\(OK) Derive m'/44'/0'/2'/0/1 Identity Key", async () => {
                        const key: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 2, 1)                        
                        expect(key).toEqual(new Uint8Array(Buffer.from("2623ec5aad0ed598fcba654d9abd24c0c3f4804d5ac5f486e618fa1c66da139a", "hex")))
                    })
                })
            })

        describe("Signing Typed Data", () => {
            it("\(OK) Sign Arbitrary Message against Schem", async () => {
                const firstKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)
    
                const message = {
                    letter: "Hello World"
                }

                const encoded: Buffer = Buffer.from(to_base64(JSON.stringify(message)))

                // Schema of what we are signing
                const jsonSchema = {
                    type: "object",
                    properties: {
                        letter: {
                            type: "string"
                        }
                    }
                }

                const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: jsonSchema } 

                const signature: Uint8Array = await cryptoService.signData(KeyContext.Address,0, 0, encoded,  metadata)
                expect(signature).toHaveLength(64)
    
                const isValid: boolean = await cryptoService.verifyWithPublicKey(signature, encoded, firstKey)
                expect(isValid).toBe(true)
            })

            it("\(FAIL) Signing attempt fails because of invalid data against Schema", async () => {    
                const message = {
                    letter: "Hello World"
                }

                const encoded: Buffer = Buffer.from(to_base64(JSON.stringify(message)))

                // Schema of what we are signing
                const jsonSchema = {
                    type: "string"
                }

                const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: jsonSchema } 
                expect(cryptoService.signData(KeyContext.Identity,0, 0, encoded,  metadata)).rejects.toThrowError()
            })

            describe("Reject Regular Transaction Signing. IF TAG Prexies are present signing must fail", () => {
                describe("Reject tags present in the encoded payload", () => {
                    it("\(FAIL) [TX] Tag", async () => {
                        const transaction: Buffer = Buffer.concat([Buffer.from("TX"), msgpack.encode(randomBytes(64))])
                        const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: {} }
    
                        const encodedTx: Buffer = Buffer.from(transaction.toString('base64'))
                        expect(cryptoService.signData(KeyContext.Identity,0, 0, encodedTx,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                    })

                    it("\(FAIL) [MX] Tag", async () => {
                        const transaction: Buffer = Buffer.concat([Buffer.from("MX"), msgpack.encode(randomBytes(64))])
                        const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: {} }
    
                        const encodedTx: Buffer = Buffer.from(transaction.toString('base64'))
                        expect(cryptoService.signData(KeyContext.Identity,0, 0, encodedTx,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                    })

                    it("\(FAIL) [Program] Tag", async () => {
                        const transaction: Buffer = Buffer.concat([Buffer.from("Program"), msgpack.encode(randomBytes(64))])
                        const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: {} }
    
                        const encodedTx: Buffer = Buffer.from(transaction.toString('base64'))
                        expect(cryptoService.signData(KeyContext.Identity,0, 0, encodedTx,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                    })

                    it("\(FAIL) [progData] Tag", async () => {
                        const transaction: Buffer = Buffer.concat([Buffer.from("progData"), msgpack.encode(randomBytes(64))])
                        const metadata: SignMetadata = { encoding: Encoding.BASE64, schema: {} }
    
                        const encodedTx: Buffer = Buffer.from(transaction.toString('base64'))
                        expect(cryptoService.signData(KeyContext.Identity,0, 0, encodedTx,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                    })  
                })
                
                it("\(FAIL) [TX] Tag", async () => {
                    const transaction: Buffer = Buffer.concat([Buffer.from("TX"), msgpack.encode(randomBytes(64))])
                    const metadata: SignMetadata = { encoding: Encoding.MSGPACK, schema: {} }
                    expect(cryptoService.signData(KeyContext.Identity,0, 0, transaction,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                })

                it("\(FAIL) [MX] Tag", async () => {
                    const transaction: Buffer = Buffer.concat([Buffer.from("MX"), msgpack.encode(randomBytes(64))])
                    const metadata: SignMetadata = { encoding: Encoding.MSGPACK, schema: {} }
                    expect(cryptoService.signData(KeyContext.Identity,0, 0, transaction,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                })

                it("\(FAIL) [Program] Tag", async () => {
                    const transaction: Buffer = Buffer.concat([Buffer.from("Program"), msgpack.encode(randomBytes(64))])
                    const metadata: SignMetadata = { encoding: Encoding.MSGPACK, schema: {} }
                    expect(cryptoService.signData(KeyContext.Identity,0, 0, transaction,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                })

                it("\(FAIL) [progData] Tag", async () => {
                    const transaction: Buffer = Buffer.concat([Buffer.from("progData"), msgpack.encode(randomBytes(64))])
                    const metadata: SignMetadata = { encoding: Encoding.MSGPACK, schema: {} }
                    expect(cryptoService.signData(KeyContext.Identity,0, 0, transaction,  metadata)).rejects.toThrowError(ERROR_BAD_DATA)
                })
            })

        })


        it("\(OK) ECDH", async () => {
            const aliceKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 0)
            const bobKey: Uint8Array = await cryptoService.keyGen(KeyContext.Address, 0, 1)

            const aliceSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Address, 0, 0, bobKey)
            const bobSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Address, 0, 1, aliceKey)

            expect(aliceSharedSecret).toEqual(bobSharedSecret)
        })

        it("\(OK) ECDH, Encrypt and Decrypt", async () => {
            const aliceKey: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 0)
            const bobKey: Uint8Array = await cryptoService.keyGen(KeyContext.Identity, 0, 1)

            const aliceSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Identity, 0, 0, bobKey)
            const bobSharedSecret: Uint8Array = await cryptoService.ECDH(KeyContext.Identity, 0, 1, aliceKey)

            expect(aliceSharedSecret).toEqual(bobSharedSecret)

            const message: Uint8Array = new Uint8Array(Buffer.from("Hello World"))
            const nonce: Uint8Array = randomBytes(crypto_secretbox_NONCEBYTES)

            // encrypt
            const cipherText: Uint8Array = crypto_secretbox_easy(message, nonce, aliceSharedSecret)

            // decrypt
            const plainText: Uint8Array = crypto_secretbox_open_easy(cipherText, nonce, bobSharedSecret)
            expect(plainText).toEqual(message)
        })

        it("Libsodium example ECDH", async () => {
            await ready
            // keypair
            const alice: KeyPair = crypto_sign_keypair()

            const alicePvtKey: Uint8Array = alice.privateKey
            const alicePubKey: Uint8Array = alice.publicKey

            const aliceXPvt: Uint8Array = crypto_sign_ed25519_sk_to_curve25519(alicePvtKey)
            const aliceXPub: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(alicePubKey)
    
            // bob
            const bob: KeyPair = crypto_sign_keypair()
            
            const bobPvtKey: Uint8Array = bob.privateKey
            const bobPubKey: Uint8Array = bob.publicKey

            const bobXPvt: Uint8Array = crypto_sign_ed25519_sk_to_curve25519(bobPvtKey)
            const bobXPub: Uint8Array = crypto_sign_ed25519_pk_to_curve25519(bobPubKey)

            // shared secret
            const aliceSecret: Uint8Array = crypto_scalarmult(aliceXPvt, bobXPub)
            const bobSecret: Uint8Array = crypto_scalarmult(bobXPvt, aliceXPub)
            expect(aliceSecret).toEqual(bobSecret)

            const aliceSharedSecret: CryptoKX = crypto_kx_client_session_keys(aliceXPub, aliceXPvt, bobXPub)
            const bobSharedSecret: CryptoKX = crypto_kx_server_session_keys(bobXPub, bobXPvt, aliceXPub)

            // bilateral encryption channels
            expect(aliceSharedSecret.sharedRx).toEqual(bobSharedSecret.sharedTx)
            expect(bobSharedSecret.sharedTx).toEqual(aliceSharedSecret.sharedRx)
        })
    })
})
