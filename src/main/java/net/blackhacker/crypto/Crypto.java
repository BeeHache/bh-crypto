package net.blackhacker.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;

/**
 *
 * @author ben
 */
abstract public class Crypto {
    final private Cipher cipher;
    final private SecureRandom secureRandom;
    
    protected  Crypto(String algorithm) throws CryptoException {
    	try {
            cipher = Cipher.getInstance(algorithm);
            secureRandom = new SecureRandom();
        } catch (Exception  e) {
    		throw new CryptoException("Could not initialize Crypto object: " + e.getLocalizedMessage(),e);
        }
    }
   
    public byte[] encrypt(byte[] data, Key key) throws CryptoException {
        return encrypt(data,key, null);
    }
    
    public byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec param) throws CryptoException {
        synchronized(cipher) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key, param);
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    public byte[] decrypt(byte[] data, Key key) throws CryptoException {
        return decrypt(data, key, null);
    }
    
    public byte[] decrypt(byte[] data, Key key, AlgorithmParameterSpec param) throws CryptoException {
        
        synchronized(cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, param);
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
   
    public Cipher getCipher()  {
        return cipher;
    }
   
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }
    
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }
}