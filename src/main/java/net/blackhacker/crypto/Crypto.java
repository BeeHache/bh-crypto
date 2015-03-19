package net.blackhacker.crypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ben
 */
abstract public class Crypto {
    final private Cipher cipher;
    final private SecureRandom secureRandom;
    final private AlgorithmParameterSpec algorithmParameterSpec;
    
    static final public byte[] DEFAULT_IV64 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb
    };

    static final public byte[] DEFAULT_IV128 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
    };    
    
    
    private static final SecureRandom sr = new SecureRandom();
    
    static protected byte[] IV64() {
        byte[] iv = new byte[8];
        sr.nextBytes(iv);
        return iv;
    }

    static protected byte[] IV128() {
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        return iv;
    }
    
    static protected byte[] KEY(int size){
        byte[] key = new byte[size / 8];
        sr.nextBytes(key);
        return key;
    }
    
    static protected SecretKeySpec KEY_BIT_CHECK(byte[] key, String algo, int b) throws CryptoException {
        byte[] a = key;
        try {
            if (a.length !=  (b /8)) {
                throw new CryptoException("key must " + b + " bits");
            }
        } catch(NullPointerException e) {
            switch(b){
                case 64:
                    a = DEFAULT_IV64;
                    break;

                case 128:
                    a = DEFAULT_IV128;
                    break;

                default:
                    throw new CryptoException("Illeagel IV bit size " + b);
            }
        }
        return new SecretKeySpec(a,algo);        
    }
    
    static protected IvParameterSpec IV_BIT_CHECK(byte[] iv, String n, int b) throws CryptoException {
        byte[] a = iv;
        try {
            if (a.length !=  (b /8)) {
                throw new CryptoException(n + " must " + b + " bits");
            }
        } catch(NullPointerException e) {
            switch(b){
                case 64:
                    a = DEFAULT_IV64;
                    break;

                case 128:
                    a = DEFAULT_IV128;
                    break;

                default:
                    throw new CryptoException("Illeagel IV bit size " + b);
            }
        }
        return new IvParameterSpec(a);
    }
    
    static protected IvParameterSpec IV64_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv,"IV", 64);
    }

    static protected IvParameterSpec IV128_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv,"IV", 128);
    }

    static protected IvParameterSpec IV192_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv,"IV", 192);
    }
    
    static protected IvParameterSpec IV256_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv,"IV", 256);
    }

    static protected SecretKeySpec KEY128_BIT_CHECK(byte[] key, String algo) throws CryptoException {
        return KEY_BIT_CHECK(key,algo, 128);
    }

    static protected SecretKeySpec KEY192_BIT_CHECK(byte[] key, String algo) throws CryptoException {
        return KEY_BIT_CHECK(key,algo, 192);
    }
    
    static protected SecretKeySpec KEY256_BIT_CHECK(byte[] key, String algo) throws CryptoException {
        return KEY_BIT_CHECK(key,algo, 256);
    }
    
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