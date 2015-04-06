package net.blackhacker.crypto;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

import org.junit.BeforeClass;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.junit.Assert.*;
import org.junit.Ignore;

public class SignerTest {
    final static private String digestAlgorithm ="SHA-256";
    
    static String passphrase;
    static String message;
    static AlgorithmParameterSpec pbeCipherParams;
    
    static SK[] friends;
    static SK[] foes;
    static SecretKey key;
    static Signer signerFriend;
    static Signer signerFoe;
    
    @BeforeClass
    static public void setup() throws SignerException {
        try {
            passphrase = "The quickbown fox jumped over the lazy dog.";
            message = "A far far better thing I do than I have ever done before.";
            
            Security.insertProviderAt(new BouncyCastleProvider(),1);            
    
            
            friends = new SK[]{SK.getInstanceDESWithECB()};
            foes = new SK[]{SK.getInstanceDESWithECB()};
            signerFriend = Signer.newInstanceDESwithMD5();
            signerFoe = Signer.newInstanceDESwithMD5();
        } catch (CryptoException ex) {
            fail(ex.getMessage());
        }
    }    
    
    @Ignore
    public void signingTest() {
        try {
            byte[] data = message.getBytes();
            byte[] signature = signerFriend.sign(data);
            assertNotNull(signature);
            
            boolean verified = signerFriend.verify(data, signature);
            assertTrue(verified);
            
            verified = signerFoe.verify(data, signature);
            assertFalse(verified);
            
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
}