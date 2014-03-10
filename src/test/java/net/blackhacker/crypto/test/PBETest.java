package net.blackhacker.crypto.test;

import java.security.Security;
import javax.crypto.SecretKey;
import org.junit.BeforeClass;
import org.junit.Test;
import java.security.spec.AlgorithmParameterSpec;
import net.blackhacker.crypto.MD;
import net.blackhacker.crypto.PBE;
import net.blackhacker.crypto.PBESigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;

public class PBETest {
    final static private String digestAlgorithm ="SHA-256";
    final static private String pbeAlgorithm = "PBEWithSHA256And256BitAES-CBC-BC";
    final static private String cipherAlgorithm = "AES/CTR/NOPADDING";
    
    static String passphrase;
    static String message;
    static AlgorithmParameterSpec pbeCipherParams;
    
    static PBE pbe;
    static PBESigner signer;
    static SecretKey key;
    static MD md;
    
    static byte[] salt = { 
        (byte) 1, (byte)2, (byte) 3, (byte)4,
        (byte) 1, (byte)2, (byte) 3, (byte)4 };
    
    @BeforeClass
    static public void setup() {
        try {
            passphrase = "The quickbown fox jumped over the lazy dog.";
            message = "A far far better thing I do than I have ever done before.";
            
            
            
            Security.insertProviderAt(new BouncyCastleProvider(),1);
            
            md = new MD(digestAlgorithm);
            pbe = new PBE(pbeAlgorithm, salt);
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
    
    @Test
    public void encryptionTest() {
        try {
            assertNotNull(pbe.generateSecretKey(passphrase));
            
            byte[] cipherbytes = pbe.encrypt(message.getBytes());
            assertNotNull(cipherbytes);
            
            byte[] clearbytes = pbe.decrypt(cipherbytes);
            assertNotNull(clearbytes);
            assertEquals(message, new String(clearbytes, "UTF-8"));
            
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
    
    @Test
    public void signingTest() {
        try {
            signer = PBESigner.newInstance(passphrase,pbeAlgorithm,digestAlgorithm, salt);

            byte[] data = message.getBytes();
            byte[] signature = signer.sign(data);
            assertNotNull(signature);
            
            boolean verified = signer.verify(data, signature);
            assertTrue(verified);
            
        } catch (Exception ex) {
            fail(ex.getMessage());
        }
    }
}