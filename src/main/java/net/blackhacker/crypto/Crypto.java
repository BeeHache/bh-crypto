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

import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *  Abstract base class for both symmetric and asymmetric encryption algorithms
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public abstract class Crypto implements Encryptor, Decryptor {

    public enum Algorithm {
        /* Cipher*/
        AES(128, SecretKeySpec.class),
        AESWrap(128, null), 
        ARCFOUR, 
        Blowfish,
        CCM,
        DES(DESKeySpec.class), 
        DESede(DESedeKeySpec.class),
        DESedeWrap,
        ECIES,
        GCM, 
        RC2, 
        RC4, 
        RC5,
        RSA,
        
        /* Digest */
        MD2(null), MD5(null), SHA1(null), SHA256(null), SHA384(null), SHA512(null);
        
        Algorithm(){
            this(null);
        }
        
        Algorithm(Class <? extends KeySpec> keySpecClass){
            this(64, keySpecClass);
        }

        Algorithm(int s, Class <? extends KeySpec> keySpecClass){
            this.blockSize = s;
            this.keySpecClass = keySpecClass;
        }
        
        public int blockSize() {
            return blockSize;
        }
        
        
        public KeySpec makeKeySpec(byte[] key) throws CryptoException {
            try {
                if (keySpecClass.equals(SecretKeySpec.class))
                    return keySpecClass
                            .getConstructor(byte[].class, String.class)
                            .newInstance(key, name());
                else
                    return keySpecClass
                            .getConstructor(byte[].class)
                            .newInstance(key);
            } catch (NoSuchMethodException | SecurityException | 
                    InstantiationException | IllegalAccessException | 
                    IllegalArgumentException | InvocationTargetException ex) {
                throw new CryptoException("Couldn't make keyspec", ex);
            }
        }
        
        final int blockSize;
        final Class <? extends KeySpec> keySpecClass;
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
    
}