package net.blackhacker.crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ben
 */
abstract public class PKBase extends Crypto {
    final private PublicKey publicKey;
    final private PrivateKey privateKey;
    
    public  PKBase(String algorithm) throws CryptoException {
        super(algorithm);
        try {
	        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
	        kpg.initialize(2048);
	        KeyPair kp = kpg.generateKeyPair();        
	        publicKey = kp.getPublic();
	        privateKey = kp.getPrivate();
        } catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
    }
    
    /**
     *
     * @param algorithm
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     */
    public PKBase(String algorithm, byte[] publicKeyEncoded, byte[] privateKeyEncoded) throws CryptoException {
        super(algorithm);
        try {
	        EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyEncoded);
	        EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
	        KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
	        publicKey = kf.generatePublic(pubSpec);
	        privateKey = kf.generatePrivate(privSpec);
        } catch(Exception e) {
        	throw new CryptoException(e);
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public byte[] encrypt(byte[] data) throws CryptoException {
        return encrypt(data, publicKey);
    }
    
    public byte[] decrypt(byte[] data) throws CryptoException {
        return decrypt(data, privateKey);
    }
    
    public byte[] getPublicKeyEncoded() {
        return getPublicKey().getEncoded();
    }
    
    public byte[] getPrivateKeyEncoded() {
        return getPrivateKey().getEncoded();
    }
}