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

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ErrorCollector;

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class EncryptorTest {
    
    static private String passphrase;
    static private String message;
    static private AlgorithmParameterSpec pbeCipherParams;
    
    static private SecretKey key;
    static private Signer signerFriend;
    static private Signer signerFoe;
    
    private final SK friend;
    private final SK foe;
    private final SK me;

    public EncryptorTest(SK friend, SK foe, SK me) {
      this.friend = friend;
      this.foe = foe;
      this.me = me;
    }

    static boolean jce() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES/ECB/PKCS5Padding") == Integer.MAX_VALUE;
        } catch (NoSuchAlgorithmException ex) {
            return false;
        }
    }    
    
    // creates the test data
    @Parameters
    public static Collection<Object[]> data() throws CryptoException {
        byte[] iv8 = new byte[8];
        byte[] iv16 = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv8);
        sr.nextBytes(iv16);
        
        SK hold;
        
        List<Object[]> l = new ArrayList<>(Arrays.asList(
            new Object[][] {
                /* DES */
                /* 0 */ {
                    hold = EncryptorFactory.newEncryptorDESWithECB(), 
                    EncryptorFactory.newEncryptorDESWithECB(), 
                    EncryptorFactory.newEncryptorDESWithECB(hold.getKeyEncoded())
                },
                /* 1 */ {
                    hold = EncryptorFactory.newEncryptorDESWithCBC(iv8), 
                    EncryptorFactory.newEncryptorDESWithCBC(iv8), 
                    EncryptorFactory.newEncryptorDESWithCBC(iv8,hold.getKeyEncoded())
                },
                /* 2 */ {
                    hold = EncryptorFactory.newEncryptorDESWithCFB(iv8),
                    EncryptorFactory.newEncryptorDESWithCFB(iv8),
                    EncryptorFactory.newEncryptorDESWithCFB(iv8,hold.getKeyEncoded())
                },
                /* 3 */ {
                    hold = EncryptorFactory.newEncryptorDESWithOFB(iv8),
                    EncryptorFactory.newEncryptorDESWithOFB(iv8),
                    EncryptorFactory.newEncryptorDESWithOFB(iv8,hold.getKeyEncoded())
                },

                /* DESede */
                /* 4 */ {
                    hold = EncryptorFactory.newEncryptorDESedeWithECB(),
                    EncryptorFactory.newEncryptorDESedeWithECB(),
                    EncryptorFactory.newEncryptorDESedeWithECB(hold.getKeyEncoded())
                },
                /* 5 */ {
                    hold = EncryptorFactory.newEncryptorDESedeWithCBC(iv8),
                    EncryptorFactory.newEncryptorDESedeWithCBC(iv8),
                    EncryptorFactory.newEncryptorDESedeWithCBC(iv8,hold.getKeyEncoded())
                },
                /* 6 */ {
                    hold = EncryptorFactory.newEncryptorDESedeWithCFB(iv8),
                    EncryptorFactory.newEncryptorDESedeWithCFB(iv8),
                    EncryptorFactory.newEncryptorDESedeWithCFB(iv8,hold.getKeyEncoded())
                },
                /* 7 */ {
                    hold = EncryptorFactory.newEncryptorDESedeWithOFB(iv8),
                    EncryptorFactory.newEncryptorDESedeWithOFB(iv8),
                    EncryptorFactory.newEncryptorDESedeWithOFB(iv8,hold.getKeyEncoded())
                },
                
                /* AES 128 */
                /* 8 */ {
                    hold = EncryptorFactory.newEncryptorAES128WithECB(),
                    EncryptorFactory.newEncryptorAES128WithECB(),
                    EncryptorFactory.newEncryptorAES128WithECB(hold.getKeyEncoded())
                },
                /* 9 */ {
                    hold = EncryptorFactory.newEncryptorAES128WithCBC(iv16),
                    EncryptorFactory.newEncryptorAES128WithCBC(iv16),
                    EncryptorFactory.newEncryptorAES128WithCBC(iv16, hold.getKeyEncoded())
                },
                /* 10 */ {
                    hold = EncryptorFactory.newEncryptorAES128WithCFB(iv16), 
                    EncryptorFactory.newEncryptorAES128WithCFB(iv16), 
                    EncryptorFactory.newEncryptorAES128WithCFB(iv16,hold.getKeyEncoded())
                },
                /* 11 */ {
                    hold = EncryptorFactory.newEncryptorAES128WithOFB(iv16),
                    EncryptorFactory.newEncryptorAES128WithOFB(iv16),
                    EncryptorFactory.newEncryptorAES128WithOFB(iv16,hold.getKeyEncoded())
                },
                /* 12 */ {
                    hold = EncryptorFactory.newEncryptorAES128WithCTR(iv16),
                    EncryptorFactory.newEncryptorAES128WithCTR(iv16),
                    EncryptorFactory.newEncryptorAES128WithCTR(iv16,hold.getKeyEncoded())
                },
            }));
        
        if (jce()) {
            l.addAll(
                Arrays.asList(
                    new Object[][] {
                    /* AES 192 */
                     {
                         hold = EncryptorFactory.newEncryptorAES192WithECB(),
                         EncryptorFactory.newEncryptorAES192WithECB(),
                         EncryptorFactory.newEncryptorAES192WithECB(hold.getKeyEncoded())
                     },
                     /*
                     {
                        hold = EncryptorFactory.newAES192WithCBC(iv16),
                        EncryptorFactory.newAES192WithCBC(iv16), 
                        EncryptorFactory.newAES192WithCBC(iv16,hold.getKeyEncoded())
                     },
                     {
                        hold = EncryptorFactory.newAES192WithCFB(iv16),
                        EncryptorFactory.newAES192WithCFB(iv16),
                        EncryptorFactory.newAES192WithCFB(iv16,hold.getKeyEncoded())
                     },
                     {
                        hold = EncryptorFactory.newAES192WithOFB(iv16),
                        EncryptorFactory.newAES192WithOFB(iv16),
                        EncryptorFactory.newAES192WithOFB(iv16,hold.getKeyEncoded())
                     },
                     {
                        hold = EncryptorFactory.newAES192WithCTR(iv16), 
                        EncryptorFactory.newAES192WithCTR(iv16), 
                        EncryptorFactory.newAES192WithCTR(iv16,hold.getKeyEncoded())
                     },
                     */

                    /* AES OCB */
                    {
                        hold = EncryptorFactory.newEncryptorAES128WithOCB(iv16), 
                        EncryptorFactory.newEncryptorAES128WithOCB(iv16), 
                        EncryptorFactory.newEncryptorAES128WithOCB(iv16,hold.getKeyEncoded())
                    },
                    /*
                    {
                        hold = EncryptorFactory.newAES192WithOCB(iv16), 
                        EncryptorFactory.newAES192WithOCB(iv16), 
                        EncryptorFactory.newAES192WithOCB(iv16,hold.getKeyEncoded())
                    },
                    {
                        hold = EncryptorFactory.newAES255WithOCB(iv16), 
                        EncryptorFactory.newAES255WithOCB(iv16), 
                        EncryptorFactory.newAES255WithOCB(iv16,hold.getKeyEncoded())
                    },
                    */
                })
            );
        }
        return l;
    }
    
    @BeforeClass
    static public void setup() throws CryptoException {
        passphrase = "The quickbown fox jumped over the lazy dog.";
        message = "A far far better thing I do than I have ever done before.";
        Security.insertProviderAt(new BouncyCastleProvider(),1);
    }

    @Rule
    public ErrorCollector collector= new ErrorCollector();
    
    @Test
    public void encryptionTest() throws CryptoException {
        byte[] friendCipherBytes = friend.encrypt(message.getBytes(StandardCharsets.UTF_8));
        assertNotNull("friend.encrypt: failed", friendCipherBytes);

        byte[] foeCipherBytes = foe.encrypt(message.getBytes(StandardCharsets.UTF_8));
        assertNotNull("foe.encrypt: failed",foeCipherBytes);
        
        boolean friendIsFoe = Arrays.equals(friendCipherBytes, foeCipherBytes);
        assertFalse("friend and foe have same key", friendIsFoe);

        byte[] clearbytes = friend.decrypt(friendCipherBytes);
        assertNotNull("friend.decrypt: clearbytes null", clearbytes);
        assertEquals("friend.decrypt: friend can't decrypt friendCipherBytes",
                message, new String(clearbytes, StandardCharsets.UTF_8));

        try {
            byte[] clearbytes2 = foe.decrypt(friendCipherBytes);
            assertFalse("foe.decrypt: foe decrypted friend's message", Arrays.equals(clearbytes, clearbytes2));
        } catch (CryptoException ex) { }
        
        byte[] friendKeyEncoded = friend.getKeyEncoded();
        assertNotNull("friend.getKeyEncoded: null", friendKeyEncoded);
        
        byte[] clearbytes2 = me.decrypt(friendCipherBytes);
        assertNotNull("me.decrypt: clearbytes null", clearbytes2);
        assertTrue("me.decrypt: failed to decrypt correctly",Arrays.equals(clearbytes, clearbytes2));
    }
}