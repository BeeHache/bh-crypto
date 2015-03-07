package net.blackhacker.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 *
 * @author ben
 */
abstract public class SKBase extends Crypto {
    private SecretKey secretKey;
    final private SecretKeyFactory skf;
    
    /**
     * 
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @throws CryptoException 
     */
    public  SKBase(String cipherAlgorithm, String keyAlgorithm) throws CryptoException {
        super(cipherAlgorithm);
        try {
            skf = SecretKeyFactory.getInstance(keyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 
     * @return
     * @throws CryptoException 
     */
    public SecretKey getSecretKey() throws CryptoException {
        if (secretKey==null) {
            throw new CryptoException("Secrete key is null");
        }
        return secretKey;
    }
    
    /**
     * 
     * @param passphrase
     * @return
     * @throws CryptoException 
     */
    public SecretKey generateSecretKey(String passphrase) throws CryptoException {
    	try {
            KeySpec ks = generateKeySpec(passphrase.toCharArray());
            return secretKey = skf.generateSecret(ks);
    	} catch(InvalidKeySpecException e) {
            throw new CryptoException("Couldn' generate secrete key:" + e.getLocalizedMessage(),e);
    	}
    }
    
    /**
     * 
     * @param data byte array in
     * @return encrypted byte array in the clear
     * @throws CryptoException
     */
    abstract public byte[] encrypt(byte[] data) throws CryptoException;
    
    /**
     * 
     * @param data encrypted byte array
     * @return byte array in the clear
     * @throws CryptoException
     */
    abstract public byte[] decrypt(byte[] data) throws CryptoException;
    
    /**
     * 
     * @param passphrase
     * @return 
     */
    abstract public KeySpec generateKeySpec(char[] passphrase);
}