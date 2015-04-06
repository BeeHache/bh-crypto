package net.blackhacker.crypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *  Abstract base class for symmetric and asymmetric encryption
 * 
 *  @author ben
 */
abstract public class Encryptor {
    
    /**
     * SecureRandom
     */
    final static private SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * default 64 Intialization Vector
     */
    static final public byte[] DEFAULT_IV64 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb
    };

    /**
     * default 128 Intialization Vector
     */
    static final public byte[] DEFAULT_IV128 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
    };

    
    /**
     * Cipher
     */
    final private Cipher cipher;
    
    /**
     * 
     */
    final private AlgorithmParameterSpec algorithmParameterSpec;
    

    
    /**
     * 
     * @return byte array of random 8 bytes (64 bits) long
     */
    static protected byte[] RANDOM_64_BITS() {
        return RANDOM_BITS(64);
    }

    /**
     * 
     * @return byte array of random 16 bytes (128 bits) long
     */
    static protected byte[] RANDOM_128_BITS() {
        return RANDOM_BITS(128);
    }
    
    /**
     * A random array of bytes
     * 
     * @param size -- size of array in bits, should be multiple of 8
     * @return A random array of bytes
     */
    static protected byte[] RANDOM_BITS(int size){
        byte[] key = new byte[size / 8];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }
    
    /**
     * Checks the size of the key and builds 
     * SecreteKeySpec object from key and algorithm
     * 
     * @param key
     * @param algorithm
     * @param size
     * @return SecretKeySpec object
     * @throws CryptoException when key is the incorrect size for the given size
     */
    static protected SecretKeySpec KEY_BIT_CHECK(
            final byte[] key, final String algorithm, final int size) 
            throws CryptoException {
        byte[] a = key;
        try {
            if (a.length !=  (size /8)) {
                throw new CryptoException("key must " + size + " bits");
            }
        } catch(NullPointerException e) {
            switch(size){
                case 64:
                    a = DEFAULT_IV64;
                    break;

                case 128:
                    a = DEFAULT_IV128;
                    break;

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }
        }
        
        return new SecretKeySpec(a, algorithm);
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

    /**
     * Verifies the size of the key is 256
     * 
     * @param key
     * @param algo
     * @return
     * @throws CryptoException
     */
    static protected SecretKeySpec KEY256_BIT_CHECK(byte[] key, String algo) throws CryptoException {
        return KEY_BIT_CHECK(key,algo, 256);
    }
    
    /**
     * Constructor
     * @param algorithm
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected  Encryptor(String algorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
    	try {
            cipher = Cipher.getInstance(algorithm);
            this.algorithmParameterSpec = algorithmParameterSpec;
        } catch (Exception e) {
            throw new CryptoException("Could not initialize Crypto object: " + e.getLocalizedMessage(),e);
        }
    }
    
    /**
     * Must be implemented by subclass
     * 
     * @param clearBytes -- array of bytes to be encrypted
     * @return -- cipher bytes
     * @throws CryptoException
     */
    abstract public byte[] encrypt(byte[] clearBytes) throws CryptoException;
    
    /**
     * Must be implemented by subclass
     * 
     * @param cipherBytes -- bytes to be decrypted
     * @return -- bytes in the clear
     * @throws CryptoException 
     */
    abstract public byte[] decrypt(byte[] cipherBytes) throws CryptoException;

    /**
     *
     * @return AlgorithmParameterSpec object
     */
    final public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }
    
    /**
     * 
     * @return Cipher
     */
    final public Cipher getCipher()  {
        return cipher;
    }
    
    /**
     * 
     * @return SecureRandom object
     */
    final static public SecureRandom getSecureRandom() {
        return SECURE_RANDOM;
    }

    /**
     *
     * @return Algorithm String
     */
    final public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    /**
     *
     * @return
     */
    final public int getBlockSize() {
        return cipher.getBlockSize();
    }
    
    /**
     *
     * @return Intialization Vector
     */
    final public byte[] getIV() {
        return cipher.getIV();
    }
}