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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

/**
 *  Abstract base class for both symmetric and asymmetric encryption algorithms
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public abstract class Crypto implements Encryptor, Decryptor {

    public enum Algorithm {
        /* Cipher*/
        AES(128, null), 
        AESWrap(128, null), 
        ARCFOUR(null), 
        Blowfish(null), 
        CCM(null), 
        DES(new KeySpecWrapper() {
            @Override
            public KeySpec wrap(byte[] keyEncoded) throws InvalidKeyException{
                return new DESKeySpec(keyEncoded);
            }
        }), 
        DESede(new KeySpecWrapper() {
            @Override
            public KeySpec wrap(byte[] keyEncoded) throws InvalidKeyException{
                return new DESedeKeySpec(keyEncoded);
            }
        }),
        DESedeWrap(null), 
        ECIES(null), 
        GCM(null), 
        RC2(null), 
        RC4(null), 
        RC5(null), 
        RSA(null),
        
        /* Digest */
        MD2(null), MD5(null), SHA1(null), SHA256(null), SHA384(null), SHA512(null);
        
        Algorithm(KeySpecWrapper keySpecWrapper){
            this.blockSize = 64;
            this.keySpecWrapper = keySpecWrapper;
        }

        Algorithm(int s, KeySpecWrapper keySpecWrapper){
            this.blockSize = s;
            this.keySpecWrapper = keySpecWrapper;
        }
        
        public int blockSize() {
            return blockSize;
        }
        
        public KeySpec wrapKey(byte[] keyEncoded) throws InvalidKeyException {
            if (keySpecWrapper != null)
                return keySpecWrapper.wrap(keyEncoded);
            
            return null;
        }
        
        final int blockSize;
        final KeySpecWrapper keySpecWrapper;
    }
    
    public enum Mode {
        /* Cipher */
        NONE(false), CBC(true), CFB(true), CTR(true), CTS(true), ECB(false),
        OFB(true), PCBC(true), OCB(true);
        
        Mode(boolean s) {
            this.hasIV = s;
        }
        
        public boolean hasIV() {
            return hasIV;
        }
    
        final boolean hasIV;
    }
    
    public enum Padding {
        /* Cipher */
        NOpADDING, ISO10126Padding, OAEPPadding, PKCS1Padding, PKCS5Padding, 
        SSL3Padding
    }
    
    final CipherAlgorithm cipherAlgorithm;
    
    /**
     * Cipher
     */
    final private Cipher cipher;
    
    /**
     * SecureRandom
     */
    final private SecureRandom secureRandom = new SecureRandom();
    
    
    /**
     * Constructor
     * 
     * @param cipherAlgorithm
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected  Crypto(final CipherAlgorithm cipherAlgorithm, final AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
    	try {
            this.cipherAlgorithm = cipherAlgorithm;
            cipher = Cipher.getInstance(cipherAlgorithm.toString());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException(
                    "Could not initialize Crypto object: " + 
                            e.getLocalizedMessage(),e);
        }
    }
    
    
    /*  Getters and Setters */
    
    
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
    final public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    /**
     * Algorithm
     * 
     * @return Algorithm String
     */
    final public String getAlgorithm() {
        return cipher.getAlgorithm();
    }
    
    
    
    /**
     * Transformation
     * 
     * @return
     */
    final public CipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }
    
    final protected String getAlgorithmString() throws NoSuchAlgorithmException {
        if (cipherAlgorithm instanceof Transformation) {
            return ((Transformation)cipherAlgorithm).algorithm.name();
        } else {
            return cipherAlgorithm.toString();
        }
    }
    
    
    /**
     * Generates byte array containing 64 bits
     * 
     * @param size size of array in bits, should be multiple of 8
     * @return A random array of bytes
     */
    final protected byte[] getRandomBits(int size) {
        int sizeInBytes = (int) Math.ceil(((double)size) / 8.0);
        byte[] array = new byte[sizeInBytes];
        secureRandom.nextBytes(array);
        return array;
    }
    
    
    final protected byte[] joinArrays(byte[] ...arrays){
        int sum=0;
        for (byte[] array : arrays) {
            if (array!=null)
                sum += array.length;
        }
        
        byte[] retval = new byte [ sum ];
        int r = 0;
        for (byte[] array : arrays) {
            if (array!=null) {
                for (byte b : array) {
                    retval[r++] = b;
                }
            }
        }
        return retval;
    }
}