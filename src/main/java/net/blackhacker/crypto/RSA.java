package net.blackhacker.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ben
 */
public class RSA extends PKBase {
    
    public RSA() throws NoSuchAlgorithmException, NoSuchPaddingException {
        super("RSA");
    }
    
    public RSA(byte[] publicKeyEncoded, byte[] privateKeyEncoded) 
            throws NoSuchAlgorithmException, InvalidKeySpecException, 
            NoSuchPaddingException {
        super("RSA",publicKeyEncoded, privateKeyEncoded);
    }
    
    public RSAPublicKey getRSAPublicKey() {
        return (RSAPublicKey) getPublicKey();
    }
    
    
    
    public RSAPrivateKey getRSAPrivateKey() {
        return (RSAPrivateKey) getPrivateKey();
    }
}
