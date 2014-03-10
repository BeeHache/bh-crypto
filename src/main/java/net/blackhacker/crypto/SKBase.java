package net.blackhacker.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author ben
 */
abstract public class SKBase extends Crypto {
    private SecretKey secretKey;
    final private SecretKeyFactory skf;
    
    public  SKBase(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(algorithm);
        skf = SecretKeyFactory.getInstance(algorithm);
    }

    public SecretKey getSecretKey() {
        if (secretKey==null) {
            throw new NullKeyException();
        }
        return secretKey;
    }
    
    public SecretKey generateSecretKey(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeySpec ks = new PBEKeySpec(passphrase.toCharArray());
        return secretKey = skf.generateSecret(ks);
    }
    
    abstract public byte[] encrypt(byte[] data);
    
    abstract public byte[] decrypt(byte[] data);
}