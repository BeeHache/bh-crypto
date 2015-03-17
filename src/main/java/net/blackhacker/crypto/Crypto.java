package net.blackhacker.crypto;

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
    final private AlgorithmParameterSpec algorithmParameterSpec;
    
    static final public byte[] DEFAULT_IV = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb
    };
    
    /**
     *
     * @param algorithm
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected  Crypto(String algorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
    	try {
            cipher = Cipher.getInstance(algorithm);
            secureRandom = new SecureRandom();
            this.algorithmParameterSpec = algorithmParameterSpec;
        } catch (Exception e) {
            throw new CryptoException("Could not initialize Crypto object: " + e.getLocalizedMessage(),e);
        }
    }
    
    /**
     *
     * @param data
     * @return
     * @throws CryptoException
     */
    abstract public byte[] encrypt(byte[] data) throws CryptoException;
    
    /**
     * 
     * @param data
     * @return
     * @throws CryptoException 
     */
    abstract public byte[] decrypt(byte[] data) throws CryptoException;

    /**
     *
     * @return
     */
    final public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }
    
    /**
     * 
     * @return 
     */
    final public Cipher getCipher()  {
        return cipher;
    }
    
    /**
     * 
     * @return 
     */
    final public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    final public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    final public int getBlockSize() {
        return cipher.getBlockSize();
    }
    
    final public byte[] getIV() {
        return cipher.getIV();
    }
}