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
                /* 0 */ { hold = SK.getInstanceDESWithECB(), SK.getInstanceDESWithECB(), SK.getInstanceDESWithECB(hold.getKeyEncoded())},               
                /* 1 */ { hold = SK.getInstanceDESWithCBC(iv8), SK.getInstanceDESWithCBC(iv8), SK.getInstanceDESWithCBC(iv8,hold.getKeyEncoded())},
                /* 2 */ { hold = SK.getInstanceDESWithCFB(iv8), SK.getInstanceDESWithCFB(iv8), SK.getInstanceDESWithCFB(iv8,hold.getKeyEncoded())},
                /* 3 */ { hold = SK.getInstanceDESWithOFB(iv8), SK.getInstanceDESWithOFB(iv8), SK.getInstanceDESWithOFB(iv8,hold.getKeyEncoded())},

                /* DESede */
                /* 4 */ { hold = SK.getInstanceDESedeWithECB(), SK.getInstanceDESedeWithECB(), SK.getInstanceDESedeWithECB(hold.getKeyEncoded())},
                /* 5 */ { hold = SK.getInstanceDESedeWithCBC(iv8), SK.getInstanceDESedeWithCBC(iv8), SK.getInstanceDESedeWithCBC(iv8,hold.getKeyEncoded())},
                /* 6 */ { hold = SK.getInstanceDESedeWithCFB(iv8), SK.getInstanceDESedeWithCFB(iv8), SK.getInstanceDESedeWithCFB(iv8,hold.getKeyEncoded())},
                /* 7 */ { hold = SK.getInstanceDESedeWithOFB(iv8), SK.getInstanceDESedeWithOFB(iv8), SK.getInstanceDESedeWithOFB(iv8,hold.getKeyEncoded())},
                
                /* AES 128 */
                /* 8 */ { hold = SK.getInstanceAES128WithECB(), SK.getInstanceAES128WithECB(), SK.getInstanceAES128WithECB(hold.getKeyEncoded())},
                /* 9 */ { hold = SK.getInstanceAES128WithCBC(iv16), SK.getInstanceAES128WithCBC(iv16), SK.getInstanceAES128WithCBC(iv16,hold.getKeyEncoded())},
                /* 10 */ { hold = SK.getInstanceAES128WithCFB(iv16), SK.getInstanceAES128WithCFB(iv16), SK.getInstanceAES128WithCFB(iv16,hold.getKeyEncoded())},
                /* 11 */ { hold = SK.getInstanceAES128WithOFB(iv16), SK.getInstanceAES128WithOFB(iv16), SK.getInstanceAES128WithOFB(iv16,hold.getKeyEncoded())},
                /* 12 */ { hold = SK.getInstanceAES128WithCTR(iv16), SK.getInstanceAES128WithCTR(iv16), SK.getInstanceAES128WithCTR(iv16,hold.getKeyEncoded())},
                                
            }));
        
        if (jce()) {
            l.addAll(
                Arrays.asList(
                    new Object[][] {
                    /* AES 192 */
                     { hold = SK.getInstanceAES192WithECB(), SK.getInstanceAES192WithECB(), SK.getInstanceAES192WithECB(hold.getKeyEncoded())},
                     //{ hold = SK.getInstanceAES192WithCBC(iv16), SK.getInstanceAES192WithCBC(iv16), SK.getInstanceAES192WithCBC(iv16,hold.getKeyEncoded())},
                     //{ hold = SK.getInstanceAES192WithCFB(iv16), SK.getInstanceAES192WithCFB(iv16), SK.getInstanceAES192WithCFB(iv16,hold.getKeyEncoded())},
                     //{ hold = SK.getInstanceAES192WithOFB(iv16), SK.getInstanceAES192WithOFB(iv16), SK.getInstanceAES192WithOFB(iv16,hold.getKeyEncoded())},
                     //{ hold = SK.getInstanceAES192WithCTR(iv16), SK.getInstanceAES192WithCTR(iv16), SK.getInstanceAES192WithCTR(iv16,hold.getKeyEncoded())},

                    /* AES OCB */
                    { hold = SK.getInstanceAES128WithOCB(iv16), SK.getInstanceAES128WithOCB(iv16), SK.getInstanceAES128WithOCB(iv16,hold.getKeyEncoded())},
                    //{ hold = SK.getInstanceAES192WithOCB(iv16), SK.getInstanceAES192WithOCB(iv16), SK.getInstanceAES192WithOCB(iv16,hold.getKeyEncoded())},
                    //{ hold = SK.getInstanceAES255WithOCB(iv16), SK.getInstanceAES255WithOCB(iv16), SK.getInstanceAES255WithOCB(iv16,hold.getKeyEncoded())},
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
        System.out.println("Testing '" + friend.getAlgorithm()+"'");
        byte[] friendCipherBytes = friend.encrypt(message.getBytes(StandardCharsets.UTF_8));
        assertNotNull("friend.encrypt: failed", friendCipherBytes);

        byte[] foeCipherBytes = foe.encrypt(message.getBytes(StandardCharsets.UTF_8));
        assertNotNull("foe.encrypt: failed",foeCipherBytes);
        
        boolean friendIsFoe = Arrays.equals(friendCipherBytes, foeCipherBytes);
        assertFalse("friend and foe have same key", friendIsFoe);

        byte[] clearbytes = friend.decrypt(friendCipherBytes);
        assertNotNull("friend.decrypt: clearbytes null", clearbytes);
        assertEquals("friend.decrypt: friend can't decrypt friendCipherBytes", message, new String(clearbytes, StandardCharsets.UTF_8));

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