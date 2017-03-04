/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2017 Benjamin King aka Blackhacker(bh@blackhacker.net)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
import javax.crypto.spec.PBEKeySpec;
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
     * @throws CryptoException
     */
    protected SK(final Transformation transformation) throws CryptoException {
        super(transformation);
        Validator.isFalse(transformation.isPBE(), Strings.NON_PBE_MSG);
        
        try {
            KeyGenerator kg = KeyGenerator.getInstance(transformation.getAlgorithmString());
            kg.init(getSecureRandom());
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                String.format(
                    "Couldn't generate key for %s : %s", 
                    transformation.toString(), 
                    e.getLocalizedMessage()), 
                e);
        }
    }
    
    /**
     *
     * @param transformation
     * @param encodedKeySpec
     * @throws CryptoException
     */
    protected SK(final Transformation transformation, final byte[] encodedKeySpec)
            throws CryptoException {
        super(transformation);
        Validator.isFalse(transformation.isPBE(), Strings.NON_PBE_MSG);
        Validator.notNull(encodedKeySpec, "encodedKeySpec");
        try {
            KeySpec spec = transformation
                .getSymetricAlgorithm()
                .makeKeySpec(encodedKeySpec);
            
            if (spec instanceof SecretKeySpec) {
                key = (Key) spec;
            } else {
                key = SecretKeyFactory
                    .getInstance(transformation.getAlgorithmString())
                    .generateSecret(spec);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_CREATE_KEY_FACT_MSG,
                    transformation.getAlgorithmString(),
                    ex.getLocalizedMessage()),
                ex);
        }
    }
    
    /**
     *
     * @param transformation
     * @param password
     * @throws CryptoException
     */
    protected SK(final Transformation transformation, final char[] password)
            throws CryptoException {
        super(transformation);
        Validator.isTrue(transformation.isPBE(), Strings.PBE_MSG);
        Validator.notNull(password, "password");
        
        String algorithm = transformation.getAlgorithmString();
        try {
            PBEKeySpec spec = new PBEKeySpec(password);
            SecretKeyFactory kf = SecretKeyFactory.getInstance(algorithm);
            key = kf.generateSecret(spec);
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_CREATE_KEY_FACT_MSG,
                algorithm,
                ex.getLocalizedMessage()),ex);
        }
    } 
    
    /**
     *
     * @param data
     * @param parameters
     * @return encrypted version data
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] data, Object... parameters) throws CryptoException {
        Validator.notNull(data, "data");
        Transformation transformation = getTransformation();
        Cipher cipher = getCipher();
        
        if (parameters==null || parameters.length==0) {
            if (isPBE())
                parameters = new Object[]{ generateSalt(), getIterationCount() };
            
            if (transformation.hasIV()){
                parameters = new Object[]{ generateIV()};
            }
        }
            
        AlgorithmParameterSpec aps = transformation.makeParameterSpec(parameters);
        
        try {
            synchronized(cipher) {                
                if (aps != null) {
                    cipher
                        .init(Cipher.ENCRYPT_MODE, key, aps, getSecureRandom());
                } else {
                    cipher
                        .init(Cipher.ENCRYPT_MODE, key, getSecureRandom());
                }
                
                return cipher.doFinal(data);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_ENCRYPT_MSG,
                getTransformation(),
                ex.getLocalizedMessage()),ex);
        }
    }
    
    /**
     * 
     * @param data
     * @param parameters
     * @return clear version of data
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data, Object... parameters) throws CryptoException {
        Validator.notNull(data, "data");
        Cipher cipher = getCipher();
        Transformation transformation = getTransformation();
        AlgorithmParameterSpec aps = transformation.makeParameterSpec(parameters);
        
        try {
            synchronized(cipher) {
                
                if (aps!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, key, aps);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }                
                
                return cipher.doFinal(data);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_DECRYPT_MSG,
                transformation,
                ex.getLocalizedMessage()),ex);
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