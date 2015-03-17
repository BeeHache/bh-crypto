package net.blackhacker.crypto;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 * @author ben
 */
public class RSA extends PKBase {
    
    public RSA() throws CryptoException {
        super("RSA", null);
    }
    
    public RSA(byte[] publicKeyEncoded, byte[] privateKeyEncoded) throws CryptoException {
        super("RSA",null,publicKeyEncoded, privateKeyEncoded);
    }
    
    public RSAPublicKey getRSAPublicKey() {
        return (RSAPublicKey) getPublicKey();
    }
    
    public RSAPrivateKey getRSAPrivateKey() {
        return (RSAPrivateKey) getPrivateKey();
    }
}
