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
    
    public  SKBase(String algorithm) throws CryptoException {
        super(algorithm);
        try {
			skf = SecretKeyFactory.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
    }

    public SecretKey getSecretKey() {
        if (secretKey==null) {
            throw new NullKeyException();
        }
        return secretKey;
    }
    
    public SecretKey generateSecretKey(String passphrase) throws CryptoException {
    	try {
    		KeySpec ks = new PBEKeySpec(passphrase.toCharArray());
    		return secretKey = skf.generateSecret(ks);
    	} catch(InvalidKeySpecException e) {
    		throw new CryptoException("Couldn' generate secrete key",e);
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
    abstract public byte[] decrypt(byte[] data) throws CryptoException ;
}