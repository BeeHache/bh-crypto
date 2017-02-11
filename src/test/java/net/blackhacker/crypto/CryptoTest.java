/*
 * The MIT License
 *
 * Copyright 2015 Benjamin King aka Blackhacker(bh@blackhacker.net)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.blackhacker.crypto;

import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.crypto.SecretKey;
import static net.blackhacker.crypto.TestSuite.jce;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.junit.BeforeClass;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Rule;
import org.junit.rules.ErrorCollector;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * @author ben
 */
public class CryptoTest {
    
    static Digester sha256 = DigesterFactory.newDigesterSHA256();
    
    static private String passphrase;
    static private byte[] message = new byte[245];  //245 is the largest data RSA encrypts
    static private AlgorithmParameterSpec pbeCipherParams;
    
    static private SecretKey key;
    
    private final Crypto friend;
    private final Crypto foe;
    private final Crypto me;

    public CryptoTest(Crypto friend, Crypto foe, Crypto me) {
      this.friend = friend;
      this.foe = foe;
      this.me = me;
    }
    
    // creates the test data
    @Parameters
    public static Collection<Crypto[]> data() throws CryptoException {
        
        Security.insertProviderAt(new BouncyCastleProvider(),1);
        
        byte[] iv8 = new byte[8];
        byte[] iv16 = new byte[16];
        String friendPassword = "The quick brown fox";
        String foePassword = "jumped over the lazy dog";
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv8);
        sr.nextBytes(iv16);
        
        SK skHold;
        PK pkHold;
        
        List<Crypto[]> l = new ArrayList<>(Arrays.asList(
            new Crypto[][] {
                /* DES */
                /* 0 */ {
                    skHold = CryptoFactory.newEncryptorDESWithECB(), 
                    CryptoFactory.newEncryptorDESWithECB(), 
                    CryptoFactory.newEncryptorDESWithECB(skHold.getKeyEncoded())
                },
                /* 1 */ {
                    skHold = CryptoFactory.newEncryptorDESWithCBC(), 
                    CryptoFactory.newEncryptorDESWithCBC(), 
                    CryptoFactory.newEncryptorDESWithCBC(skHold.getKeyEncoded())
                },
                /* 2 */ {
                    skHold = CryptoFactory.newEncryptorDESWithCFB(),
                    CryptoFactory.newEncryptorDESWithCFB(),
                    CryptoFactory.newEncryptorDESWithCFB(skHold.getKeyEncoded())
                },
                /* 3 */ {
                    skHold = CryptoFactory.newEncryptorDESWithOFB(),
                    CryptoFactory.newEncryptorDESWithOFB(),
                    CryptoFactory.newEncryptorDESWithOFB(skHold.getKeyEncoded())
                },

                /* DESede */
                /* 4 */ {
                    skHold = CryptoFactory.newEncryptorDESedeWithECB(),
                    CryptoFactory.newEncryptorDESedeWithECB(),
                    CryptoFactory.newEncryptorDESedeWithECB(skHold.getKeyEncoded())
                },
                /* 5 */ {
                    skHold = CryptoFactory.newEncryptorDESedeWithCBC(),
                    CryptoFactory.newEncryptorDESedeWithCBC(),
                    CryptoFactory.newEncryptorDESedeWithCBC(skHold.getKeyEncoded())
                },
                /* 6 */ {
                    skHold = CryptoFactory.newEncryptorDESedeWithCFB(),
                    CryptoFactory.newEncryptorDESedeWithCFB(),
                    CryptoFactory.newEncryptorDESedeWithCFB(skHold.getKeyEncoded())
                },
                /* 7 */ {
                    skHold = CryptoFactory.newEncryptorDESedeWithOFB(),
                    CryptoFactory.newEncryptorDESedeWithOFB(),
                    CryptoFactory.newEncryptorDESedeWithOFB(skHold.getKeyEncoded())
                },
                
                /* AES 128 */
                /* 8 */ {
                    skHold = CryptoFactory.newEncryptorAES128WithECB(),
                    CryptoFactory.newEncryptorAES128WithECB(),
                    CryptoFactory.newEncryptorAES128WithECB(skHold.getKeyEncoded())
                },
                /* 9 */ {
                    skHold = CryptoFactory.newEncryptorAES128WithCBC(),
                    CryptoFactory.newEncryptorAES128WithCBC(),
                    CryptoFactory.newEncryptorAES128WithCBC(skHold.getKeyEncoded())
                },
                /* 10 */ {
                    skHold = CryptoFactory.newEncryptorAES128WithCFB(),
                    CryptoFactory.newEncryptorAES128WithCFB(),
                    CryptoFactory.newEncryptorAES128WithCFB(skHold.getKeyEncoded())
                },
                /* 11 */ {
                    skHold = CryptoFactory.newEncryptorAES128WithOFB(),
                    CryptoFactory.newEncryptorAES128WithOFB(),
                    CryptoFactory.newEncryptorAES128WithOFB(skHold.getKeyEncoded())
                },
                /* 12 */ {
                    skHold = CryptoFactory.newEncryptorAES128WithCTR(),
                    CryptoFactory.newEncryptorAES128WithCTR(),
                    CryptoFactory.newEncryptorAES128WithCTR(skHold.getKeyEncoded())
                },
                
                /* PBE */

                /* 13 */ {
                    CryptoFactory.newEncryptorPBEWithMD5AndDES(friendPassword),
                    CryptoFactory.newEncryptorPBEWithMD5AndDES(foePassword),
                    CryptoFactory.newEncryptorPBEWithMD5AndDES(friendPassword)
                },                      

                /* 14 */ {
                    CryptoFactory.newEncryptorPBEWithSHA1AndDESede(friendPassword),
                    CryptoFactory.newEncryptorPBEWithSHA1AndDESede(foePassword),
                    CryptoFactory.newEncryptorPBEWithSHA1AndDESede(friendPassword)
                },  
                
                /* RSA */
                /* 15  */ {
                    pkHold = CryptoFactory.newEncryptorRSAWithECB(),
                    CryptoFactory.newEncryptorRSAWithECB(),
                    CryptoFactory.newEncryptorRSAWithECB(
                        pkHold.getPublicKeyEncoded(),
                        pkHold.getPrivateKeyEncoded()
                    )
                },
            }));
        
        if (jce()) {
            l.addAll(
                Arrays.asList(
                    new Crypto[][] {
                    /* AES 192 */
                     {
                         skHold = CryptoFactory.newEncryptorAES192WithECB(),
                         CryptoFactory.newEncryptorAES192WithECB(),
                         CryptoFactory.newEncryptorAES192WithECB(skHold.getKeyEncoded())
                     },
                     /*
                     {
                        skHold = CryptoFactory.newAES192WithCBC(iv16),
                        CryptoFactory.newAES192WithCBC(iv16), 
                        CryptoFactory.newAES192WithCBC(iv16,skHold.getKeyEncoded())
                     },
                     {
                        skHold = CryptoFactory.newAES192WithCFB(iv16),
                        CryptoFactory.newAES192WithCFB(iv16),
                        CryptoFactory.newAES192WithCFB(iv16,skHold.getKeyEncoded())
                     },
                     {
                        skHold = CryptoFactory.newAES192WithOFB(iv16),
                        CryptoFactory.newAES192WithOFB(iv16),
                        CryptoFactory.newAES192WithOFB(iv16,skHold.getKeyEncoded())
                     },
                     {
                        skHold = CryptoFactory.newAES192WithCTR(iv16), 
                        CryptoFactory.newAES192WithCTR(iv16), 
                        CryptoFactory.newAES192WithCTR(iv16,skHold.getKeyEncoded())
                     },
                     */

                    /* AES OCB */
                    {
                        skHold = CryptoFactory.newEncryptorAES128WithOCB(), 
                        CryptoFactory.newEncryptorAES128WithOCB(), 
                        CryptoFactory.newEncryptorAES128WithOCB(skHold.getKeyEncoded())
                    },
                    /*
                    {
                        skHold = CryptoFactory.newAES192WithOCB(iv16), 
                        CryptoFactory.newAES192WithOCB(iv16), 
                        CryptoFactory.newAES192WithOCB(iv16,skHold.getKeyEncoded())
                    },
                    {
                        skHold = CryptoFactory.newAES255WithOCB(iv16), 
                        CryptoFactory.newAES255WithOCB(iv16), 
                        CryptoFactory.newAES255WithOCB(iv16,skHold.getKeyEncoded())
                    },
                    */

                    /* 14 */ {
                        CryptoFactory.newEncryptorPBEWithMD5AndTripleDES(friendPassword),
                        CryptoFactory.newEncryptorPBEWithMD5AndTripleDES(foePassword),
                        CryptoFactory.newEncryptorPBEWithMD5AndTripleDES(friendPassword)
                    },

                    /* 13 */ {
                        CryptoFactory.newEncryptorPBEWithSHAAnd3KeyTripleDES(friendPassword),
                        CryptoFactory.newEncryptorPBEWithSHAAnd3KeyTripleDES(foePassword),
                        CryptoFactory.newEncryptorPBEWithSHAAnd3KeyTripleDES(friendPassword)
                    },                

                    /* 14 */ {
                        CryptoFactory.newEncryptorPBEWithSHA256And256BitAES(friendPassword),
                        CryptoFactory.newEncryptorPBEWithSHA256And256BitAES(foePassword),
                        CryptoFactory.newEncryptorPBEWithSHA256And256BitAES(friendPassword)
                    },
                })
            );
        }
        return l;
    }
    
    @BeforeClass
    static public void setup() throws CryptoException {
        SecureRandom sr = new SecureRandom();
        passphrase = "The quickbown fox jumped over the lazy dog.";
        sr.nextBytes(message);
        //message = "A far far better thing I do than I have ever done before.".getBytes(StandardCharsets.UTF_8);
        Security.insertProviderAt(new BouncyCastleProvider(),1);
    }

    @Rule
    public ErrorCollector collector= new ErrorCollector();
    
    public void encryptDecryptTest() throws CryptoException {
        String algorithm = me.getTransformation().toString();
        
        byte[] friendCipherBytes = friend.encrypt(message);
        assertNotNull(algorithm + ":friend.encrypt: failed", friendCipherBytes);
        
        byte[] friendClearBytes = friend.decrypt(friendCipherBytes);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt itself", 
                message, friendClearBytes);
        
        byte[] meCipherBytes = me.encrypt(message);
        assertNotNull(algorithm + ":me.encrypt: failed", meCipherBytes); 
        
        byte[] meClearBytes = me.decrypt(meCipherBytes);
        assertNotNull(algorithm + ":me.encrypt: failed", meClearBytes);
        assertArrayEquals(algorithm + ":me doesn't decrypt itself",
                meClearBytes, message);

        friendClearBytes = friend.decrypt(meCipherBytes);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt me", 
                message, friendClearBytes);
        
        meClearBytes = me.decrypt(friendCipherBytes);
        assertNotNull(algorithm + ":me.decrypt: failed", meClearBytes);
        assertArrayEquals(algorithm + ":me doesn't decrypt friend", 
                message, friendClearBytes);
        
        try {
            byte[] clearbytes2 = foe.decrypt(friendCipherBytes);
            assertFalse(
                    algorithm + ":foe.decrypt: foe decrypted friend's message", 
                    Arrays.equals(friendClearBytes, clearbytes2));
        } catch (CryptoException ex) {
            //
        }

        try {
            byte[] clearbytes2 = foe.decrypt(meCipherBytes);
            assertFalse(
                    algorithm + ":foe.decrypt: foe decrypted me's message", 
                    Arrays.equals(friendClearBytes, clearbytes2));
        } catch (CryptoException ex) {
            //
        }
        
        if (me instanceof PK){
            PK pk = (PK)me;
            
            try {
                Signer meSigner = pk.getSigner(sha256);
                Signer foeSigner = ((PK)foe).getSigner(sha256);
                byte[] signature = meSigner.sign(message);
                Verifier verifier = CryptoFactory
                        .newEncryptorRSAWithECB(pk.getPublicKeyEncoded())
                        .getVerifier(sha256);
                
                Verifier foeVerifier = CryptoFactory
                        .newEncryptorRSAWithECB(((PK)foe).getPublicKeyEncoded())
                        .getVerifier(sha256);
                
                assertTrue(algorithm + ":verifier.verify: Did not verify", 
                        verifier.verify(message, signature));
                
                assertFalse(algorithm + ":verifier.verify: Did not verify", 
                        foeVerifier.verify(message, signature));
                
            } catch (SignerException ex) {
                fail(ex.getLocalizedMessage());
            }
        }
    }
}