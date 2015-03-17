package net.blackhacker.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author ben
 */
public class PBE extends SKBase {
    final private static int ITERATION = 5000;
    
    public PBE(String cipherAlgorithm, String keyAlgorithm, String passphrase) throws CryptoException {
        super(
            cipherAlgorithm,
             keyAlgorithm,
             new PBEParameterSpec(new byte[8], ITERATION),
             new PBEKeySpec(
                     new String(new MD("MD5").digest(passphrase.getBytes(StandardCharsets.UTF_8))).toCharArray()
             )
        );
        
    }
}
