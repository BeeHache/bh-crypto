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
import java.util.Arrays;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Factory for class for Symmetric or SecretKey algorithms.
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class SK extends Crypto {
    final private Key key;

    /**
     *
     * @param transformation
     * @param keySize
     * @throws CryptoException
     */
    protected SK(final Transformation transformation, int keySize)
            throws CryptoException {
        super(transformation, null);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(getAlgorithmString());
            kg.init(keySize);
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory", e);
        }
    }
    
    /**
     *
     * @param transformation
     * @param algorithmParameterSpec
     * @throws CryptoException
     */
    protected SK(final Transformation transformation,
            final AlgorithmParameterSpec algorithmParameterSpec)
            throws CryptoException {
        super(transformation, algorithmParameterSpec);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(getAlgorithmString());
            kg.init(getSecureRandom());
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory", e);
        }
    }
    
    /**
     *
     * @param cipherAlgorithm
     * @param algorithmParameterSpec
     * @param spec
     * @throws CryptoException
     */
    protected SK(final CipherAlgorithm cipherAlgorithm, 
            final AlgorithmParameterSpec algorithmParameterSpec, 
            final KeySpec spec)
            throws CryptoException {
        super(cipherAlgorithm, algorithmParameterSpec);
        try {
            if (spec instanceof SecretKeySpec) {
                key = (Key) spec;
            } else {
                key = SecretKeyFactory.getInstance(getAlgorithmString()).generateSecret(spec);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException("Couldn't create key factory: " + ex.getLocalizedMessage(),ex);
        }
    }
    
    Transformation getTransormation() {
        return (Transformation) getCipherAlgorithm();
    }
    
    /**
     *
     * @param data
     * @return encrypted version data
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        
        final Transformation transformation = getTransormation(); 

        try {
            synchronized(cipher) {
                byte[] iv = null;
                
                if (transformation.hasIV()) {
                    iv = new byte[transformation.getBlockSizeBytes()];
                    secureRandom.nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), secureRandom);                    
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
                }
                
                byte[] cipherBytes = cipher.doFinal(data);

                return Utils.joinArrays(iv, cipherBytes);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                "Could not encrypt data:" + ex.getLocalizedMessage(),
                ex);
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
        Cipher cipher = getCipher();

        final Transformation transformation = getTransormation();
        
        try {
            synchronized(cipher) {
                int ivSize = 0;
                if (transformation.hasIV()) {
                    ivSize = transformation.getBlockSizeBytes();
                    byte[] iv = Arrays.copyOf(data, ivSize);
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }
                
                return cipher.doFinal(data, ivSize, data.length - ivSize);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                    "Could not decrypt data: " +
                    getAlgorithm() + ":" +
                    ex.getLocalizedMessage(),ex);
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