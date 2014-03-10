package net.blackhacker.crypto.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import org.junit.BeforeClass;
import org.junit.Test;
import java.util.Arrays;
import net.blackhacker.crypto.RSA;
import net.blackhacker.crypto.RSASigner;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;

public class RSATest {
    
    final static private String digestAlgorithm ="SHA256";
    
    static String passphrase;
    static String message;
    
    static RSA rsa;
    static RSASigner signer;
    
    static KeyPair keyPair;
    
    @BeforeClass
    static public void setup() {
        try {
            passphrase = "The quickbown fox jumped over the lazy dog.";
            message = "A far far better thing I do than I have ever done before.";

            Security.insertProviderAt(new BouncyCastleProvider(),1);
            
            rsa = new RSA();
            assertNotNull(rsa.getPublicKey());
            assertNotNull(rsa.getPrivateKey());
            
            signer = RSASigner.newInstance(digestAlgorithm);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            keyPair = kpg.generateKeyPair();             
           
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }

    @Test()
    public void encryptionTest() {
        try {
            byte[] ciphertext1 = rsa.encrypt(message.getBytes());
            assertNotNull(ciphertext1);

            byte[] cleartext = rsa.decrypt(ciphertext1);
            assertNotNull(cleartext);
            
            assertTrue(Arrays.equals(cleartext, message.getBytes()));
            
            byte[] ciphertext2 = rsa.encrypt(message.getBytes(),keyPair.getPublic());
            assertNotNull(ciphertext2);

            cleartext = rsa.decrypt(ciphertext2,keyPair.getPrivate());
            assertNotNull(cleartext);
            
            assertTrue(Arrays.equals(cleartext, message.getBytes()));
        } catch(Exception e) {
            fail(e.getLocalizedMessage());
        }
    }

    @Test
    public void signingTest() {
        try {
            byte[] data = Base64.decodeBase64(message.getBytes());
            byte[] signature = signer.sign(data,rsa.getRSAPrivateKey());
            assertNotNull(signature);
            
            boolean verified = signer.verify(data, signature,rsa.getRSAPublicKey());
            assertTrue(verified);

            verified = signer.verify(data, signature,(RSAPublicKey)keyPair.getPublic());
            assertFalse(verified);
            
        } catch (Exception ex) {
            fail("EXCEPTION:" + ex.getMessage());
        }
    }
}