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
public class SK extends Crypto {
    final private Key key;
    
    protected SK(Transformation transformation, Object... parameters) throws CryptoException{
        super(transformation);
        try {
            if (parameters.length==0){
                KeyGenerator kg = KeyGenerator
                    .getInstance(transformation.getAlgorithmString());                
                kg.init(getSecureRandom());
                key = kg.generateKey();
            } else {
                KeySpec spec = transformation.makeKeySpec(parameters);
                if(spec instanceof SecretKeySpec) {
                    key = (Key)spec;
                } else {
                    SecretKeyFactory kf = SecretKeyFactory
                        .getInstance(transformation.getAlgorithmString());
                    key = kf.generateSecret(spec);
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
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
     * @param data
     * @return encrypted version data
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "data");
        Transformation transformation = getTransformation();
        Cipher cipher = getCipher();
        AlgorithmParameterSpec aps=null;
        byte[] iv = null;
        byte[] salt = null;
        int iterationCount;
        
        if (isPBE()) {
            salt = generateSalt();
            iterationCount = getIterationCount();
            aps = transformation.makeParameterSpec(salt, iterationCount);
        }
        
        if (transformation.hasIV()) {
            iv = generateIV();
            aps = transformation.makeParameterSpec(iv);
        }
        
        try {
            synchronized(cipher) {                
                if (aps != null) {
                    cipher
                        .init(Cipher.ENCRYPT_MODE, key, aps, getSecureRandom());
                } else {
                    cipher
                        .init(Cipher.ENCRYPT_MODE, key, getSecureRandom());
                }
                
                byte[] cipherbytes = cipher.doFinal(data);
                if (iv!=null) {
                    return concat(iv, cipherbytes);
                }
                if (salt!=null){
                    return concat(salt, cipherbytes);
                }
                return cipherbytes;
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_ENCRYPT_MSG_FMT,
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
    public byte[] decrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "data");
        Cipher cipher = getCipher();
        Transformation transformation = getTransformation();
        AlgorithmParameterSpec aps = null;
        byte[] iv = null;
        byte[] salt = null;
        byte[] cipherBytes = data;
        
        if (transformation.isPBE()) {
            salt = new byte[ transformation.getBlockSizeBytes() ];
            cipherBytes = new byte[data.length - salt.length];
            split(data, salt, cipherBytes);
            aps = transformation.makeParameterSpec(salt, getIterationCount());
        } else if (transformation.hasIV()) {
            iv = new byte[transformation.getBlockSizeBytes()];
            cipherBytes = new byte[data.length - iv.length];
            split(data, iv, cipherBytes);
            aps = transformation.makeParameterSpec(iv);  
        } 
        
        try {
            synchronized(cipher) {
                
                if (aps!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, key, aps);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }                
                
                return cipher.doFinal(cipherBytes);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_DECRYPT_MSG_FMT,
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