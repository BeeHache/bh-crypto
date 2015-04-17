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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 *  Abstract base class for both symmetric and asymmetric encryption algorithms
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 *  @see Encryptor
 */
abstract public class EncryptorBase implements Encryptor {

    
    /**
     * Cipher
     */
    final private Cipher cipher;
    
    /**
     * SecureRandom
     */
    final private SecureRandom secureRandom = new SecureRandom();
    
    /**
     * 
     */
    final private AlgorithmParameterSpec algorithmParameterSpec;
    
    /**
     * Constructor
     * 
     * @param algorithm
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected  EncryptorBase(String algorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
    	try {
            cipher = Cipher.getInstance(algorithm);
            this.algorithmParameterSpec = algorithmParameterSpec;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("Could not initialize Crypto object: " + e.getLocalizedMessage(),e);
        }
    }
    
    
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
     * Block size
     * 
     * @return block size
     */
    final public int getBlockSize() {
        return cipher.getBlockSize();
    }
    
    /**
     *Intialization Vector
     * 
     * @return Intialization Vector
     */
    final public byte[] getIV() {
        return cipher.getIV();
    }
}