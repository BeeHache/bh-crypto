package net.blackhacker.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CryptoTest {
    
    static String passphrase;
    static String message;
    static AlgorithmParameterSpec pbeCipherParams;
    
    static SecretKey key;
    static Signer signerFriend;
    static Signer signerFoe;
    
    private final SKBase friend;
    private final SKBase foe;
    private final SKBase me;

    public CryptoTest(SKBase friend, SKBase foe, SKBase me) {
      this.friend = friend;
      this.foe = foe;
      this.me = me;
    }

    // creates the test data
    @Parameters
    public static Collection<Object[]> data() throws CryptoException {
        byte[] iv8 = new byte[8];
        byte[] iv16 = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv8);
        sr.nextBytes(iv16);
        
        SKBase hold;
        
        return Arrays.asList(
            new Object[][] {
                /* DES */
                { hold = SKBase.getInstanceDESWithECB(), SKBase.getInstanceDESWithECB(), SKBase.getInstanceDESWithECB(hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESWithCBC(iv8), SKBase.getInstanceDESWithCBC(iv8), SKBase.getInstanceDESWithCBC(iv8,hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESWithCFB(iv8), SKBase.getInstanceDESWithCFB(iv8), SKBase.getInstanceDESWithCFB(iv8,hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESWithOFB(iv8), SKBase.getInstanceDESWithOFB(iv8), SKBase.getInstanceDESWithOFB(iv8,hold.getKeyEncoded())},

                /* DESede */
                { hold = SKBase.getInstanceDESedeWithECB(), SKBase.getInstanceDESedeWithECB(), SKBase.getInstanceDESedeWithECB(hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESedeWithCBC(iv8), SKBase.getInstanceDESedeWithCBC(iv8), SKBase.getInstanceDESedeWithCBC(iv8,hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESedeWithCFB(iv8), SKBase.getInstanceDESedeWithCFB(iv8), SKBase.getInstanceDESedeWithCFB(iv8,hold.getKeyEncoded())},
                { hold = SKBase.getInstanceDESedeWithOFB(iv8), SKBase.getInstanceDESedeWithOFB(iv8), SKBase.getInstanceDESedeWithOFB(iv8,hold.getKeyEncoded())},
                
                /* AES */
                { hold = SKBase.getInstanceAESWithCBC(iv16), SKBase.getInstanceAESWithCBC(iv16), SKBase.getInstanceAESWithCBC(iv16,hold.getKeyEncoded())},
            });
    }
    
    @BeforeClass
    static public void setup() throws CryptoException {
        passphrase = "The quickbown fox jumped over the lazy dog.";
        message = "A far far better thing I do than I have ever done before.";
        Security.insertProviderAt(new BouncyCastleProvider(),1);
    }
    
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
            foe.decrypt(friendCipherBytes);
            fail("foe.decrypt: foe decrypted friend's message");
        } catch (CryptoException ex) { }
        
        byte[] friendKeyEncoded = friend.getKeyEncoded();
        assertNotNull("friend.getKeyEncoded: null", friendKeyEncoded);
        
        byte[] clearbytes2 = me.decrypt(friendCipherBytes);
        assertNotNull("me.decrypt: clearbytes null", clearbytes2);
        assertTrue("me.decrypt: failed to decrypt correctly",Arrays.equals(clearbytes, clearbytes2));
    }
}