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
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    public  PKBase(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(algorithm);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();        
        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
    }
    
    /**
     *
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     */
    public PKBase(String algorithm, byte[] publicKeyEncoded, byte[] privateKeyEncoded) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        super(algorithm);
        EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyEncoded);
        EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
        KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
        publicKey = kf.generatePublic(pubSpec);
        privateKey = kf.generatePrivate(privSpec);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public byte[] encrypt(byte[] data) {
        return encrypt(data, publicKey);
    }
    
    public byte[] decrypt(byte[] data) {
        return decrypt(data, privateKey);
    }
    
    public void setPublicKeyEncoded(byte[] encoded) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
            publicKey = kf.generatePublic(spec);
        } catch (Exception ex) {
            Logger.getLogger(PKBase.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void setPrivateKeyEncoded(byte[] encoded) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
            privateKey = kf.generatePrivate(spec);
        } catch (Exception ex) {
            Logger.getLogger(PKBase.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public byte[] getPublicKeyEncoded() {
        return getPublicKey().getEncoded();
    }
    
    public byte[] getPrivateKeyEncoded() {
        return getPrivateKey().getEncoded();
    }
}