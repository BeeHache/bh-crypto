/*
 * The MIT License
 *
 * Copyright 2015 Benjamin King aka Blackhacker(bh@blackhacker.net)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.blackhacker.crypto;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *  Abstract base class for symmetric and asymmetric encryption
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
abstract public class Encryptor {
    
    /**
     * SecureRandom
     */
    final static private SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * default 64 bit Intialization Vector
     */
    static final public byte[] DEFAULT_IV64 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb
    };

    /**
     * default 128 bit Intialization Vector
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
     * Generates byte array containing 64 bits
     * @return byte array of random 8 bytes (64 bits) long
     */
    static protected byte[] RANDOM_64_BITS() {
        return RANDOM_BITS(64);
    }

    /**
     * Generates byte array containing 128 bits
     * @return byte array of random 16 bytes (128 bits) long
     */
    static protected byte[] RANDOM_128_BITS() {
        return RANDOM_BITS(128);
    }
    
    /**
     * Generates byte array containing 192 bits
     * @return byte array of random 34 bytes (192 bits) long
     */
    static protected byte[] RANDOM_192_BITS() {
        return RANDOM_BITS(192);
    }
    
    /**
     * Generates byte array containing 64 bits
     * 
     * @param size size of array in bits, should be multiple of 8
     * @return A random array of bytes
     */
    static protected byte[] RANDOM_BITS(int size) {
        int sizeInBytes =(int) Math.ceil(((double)size) / 8.0);
        byte[] key = new byte[sizeInBytes];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }
    
    /**
     * Checks the key is the given size in bits and builds SecreteKeySpec object
     * from key and algorithm
     * 
     * @param key encoded bytes of secret key. If null then a random key is generated.
     * @param algorithm Algorithm name
     * @param size size of key in bits. It should be (64, 128, 192 or 256) if key
     * is null
     * @return SecretKeySpec object
     * @throws CryptoException when key is the incorrect size for the given size
     * @see javax.crypto.spec.SecretKeySpec
     */
    static protected SecretKeySpec KEY_BIT_CHECK(final byte[] key, final String algorithm, final int size) 
            throws CryptoException {
        
        if (key==null){
            switch(size){
                case 64:
                case 128:
                case 192:
                case 256:
                    return new SecretKeySpec(RANDOM_BITS(size), algorithm);

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }            
        } else if (key.length !=  (size / 8)){
            throw new CryptoException("key must " + size + " bits");
        }
        
        return new SecretKeySpec(key, algorithm);
    }
    /**
     * Verifies the size of IV, and wraps with IvParameterSpec
     * 
     * @param iv byte array of IV. if NULL then DEFAULT_IV64 or DEFAULT_IV128 is
     * used
     * @param size expected size of IVin bits. Should be 64 or 128.
     * @return IvParameterSpec object from iv
     * @throws CryptoException 
     * @see javax.crypto.spec.IvParameterSpec
     */
    static protected IvParameterSpec IV_BIT_CHECK(final byte[] iv, int size)
            throws CryptoException {
        
        if (iv == null) {
            switch(size) {
                case 64:
                    return new IvParameterSpec(DEFAULT_IV64);

                case 128:
                    return new IvParameterSpec(DEFAULT_IV128);

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }
        } else if (iv.length !=  (size / 8)) {
            throw new CryptoException("IV must " + size + " bits");
        }
            return new IvParameterSpec(iv);
    }
    
    /**
     * Verifies that the IV is 64 bits. Same as IV_BIT_CHECK(iv,64)
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static protected IvParameterSpec IV64_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 64);
    }
    /**
     * Verifies that the IV is 128 bits. Same as IV_BIT_CHECK(iv,128)
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static protected IvParameterSpec IV128_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 128);
    }
    /**
     * Verifies that the IV is 192 bits. Same as IV_BIT_CHECK(iv,192)
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static protected IvParameterSpec IV192_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 192);
    }
    
    /**
     * Verifies that the IV is 128 bits. Same as IV_BIT_CHECK(iv,256)
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */    
    static protected IvParameterSpec IV256_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 256);
    }

    /**
     * Checks the key is 128 bits and builds SecreteKeySpec object from key and algorithm
     * @param key Key object encoded in bytes
     * @param algorithm 
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see javax.crypto.spec.SecretKeySpec
     */
    static protected SecretKeySpec KEY128_BIT_CHECK(byte[] key, String algorithm) throws CryptoException {
        return KEY_BIT_CHECK(key, algorithm, 128);
    }
    
    /**
     * Checks the key is 192 bits and builds SecreteKeySpec object from key and algorithm
     * @param key Key object encoded in bytes
     * @param algorithm 
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see javax.crypto.spec.SecretKeySpec
     */
    static protected SecretKeySpec KEY192_BIT_CHECK(byte[] key, String algorithm) throws CryptoException {
        return KEY_BIT_CHECK(key, algorithm, 192);
    }

    /**
     * Verifies the size of the key is 256
     * 
     * @param key
     * @param algo
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see SecretKeySpec
     */
    static protected SecretKeySpec KEY256_BIT_CHECK(byte[] key, String algo) throws CryptoException {
        return KEY_BIT_CHECK(key,algo, 256);
    }
    
    /**
     * Constructor
     * 
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
    
    
    /*  Getters and Setters */
    
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
     * @return block size
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