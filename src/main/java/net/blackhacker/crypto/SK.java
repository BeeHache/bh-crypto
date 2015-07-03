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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * Factory for class for Symmetric or SecretKey algorithms.
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class SK extends EncryptorBase {
    final private Key key;

    /**
     *
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param keySize
     * @throws CryptoException
     */
    protected SK(String cipherAlgorithm, String keyAlgorithm, int keySize)
            throws CryptoException {
        super(cipherAlgorithm, null);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(keyAlgorithm);
            kg.init(keySize);
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory", e);
        }
    }
    
    /**
     *
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected SK(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec)
            throws CryptoException {
        super(cipherAlgorithm, algorithmParameterSpec);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(keyAlgorithm);
            kg.init(getSecureRandom());
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory", e);
        }
    }
    
    /**
     *
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param algorithmParameterSpec
     * @param spec
     * @throws CryptoException
     */
    protected SK(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec, KeySpec spec)
            throws CryptoException {
        super(cipherAlgorithm, algorithmParameterSpec);
        try {
            if (spec instanceof SecretKeySpec) {
                key = (Key) spec;
            } else {
                key = SecretKeyFactory.getInstance(keyAlgorithm).generateSecret(spec);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException("Couldn't create key factory: " + ex.getLocalizedMessage(),ex);
        }
    }
    
    /**
     *
     * @param data
     * @return encrypted version data
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        AlgorithmParameterSpec param = getAlgorithmParameterSpec();
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        
        synchronized (cipher) {
            try {
                if (param != null) {
                    cipher.init(Cipher.ENCRYPT_MODE, key, param, secureRandom);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
                }
                
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException(
                    "Could not encrypt data:" + ex.getLocalizedMessage(),
                    ex);
            }
        }
    }
    
    /**
     * 
     * @param data
     * @return clear version of data
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        AlgorithmParameterSpec param = getAlgorithmParameterSpec();
        Cipher cipher = getCipher();
        
        synchronized(cipher) {
            try {
                if (param!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, getKey(), param);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, getKey());
                }
                return cipher.doFinal(data);
            } catch (CryptoException | InvalidKeyException | InvalidAlgorithmParameterException |
                    IllegalBlockSizeException | BadPaddingException ex) {
            	throw new CryptoException(
                        "Could not decrypt data: " +
                        getAlgorithm() + ":" +
                        ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    /**
     * 
     * @return internal Key object
     * @throws CryptoException 
     * @see Key
     */
    public Key getKey() throws CryptoException {
        return key;
    }
    
    /**
     * 
     * @return Key in bytes
     */
    public byte[] getKeyEncoded() {
        return key.getEncoded();
    }
}