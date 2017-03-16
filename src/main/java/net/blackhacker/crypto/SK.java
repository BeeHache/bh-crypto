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
 * Object that implements for class for Symmetric or SecretKey algorithms
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class SK extends Crypto {
    final private Key key;
        
    protected SK(Transformation transformation, Object... parameters) throws CryptoException{
        super(transformation, parameters);
        try {
            switch(parameters.length) {
                case 0:
                    KeyGenerator kg = KeyGenerator
                        .getInstance(transformation.getAlgorithmString());                
                    kg.init(getSecureRandom());
                    key = kg.generateKey();
                    break;
                    
                default:
                    KeySpec spec = makeKeySpec(parameters);
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
     * encrypts byte arrays
     * 
     * @param data to be encrypted
     * @return encrypted version data
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "data");
        Cipher cipher = getCipher();
        AlgorithmParameterSpec aps=null;
        byte[] iv = null;
        
        if(hasParameters()){
            aps = makeParameterSpec(getParameters());
        } else if (hasIV()) {
            iv = generateIV();
            aps = makeParameterSpec(iv);
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
                    return Utils.concat(iv, cipherbytes);
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
     * Decrypts an encrypted byte array
     * 
     * @param data encrypted byte array
     * @return clear version of data
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "data");
        Cipher cipher = getCipher();
        AlgorithmParameterSpec aps = null;
        byte[] iv;
        byte[] cipherBytes = data;
        
        if (hasParameters()){
            aps = makeParameterSpec(getParameters());
            
        } else if (hasIV()) {
            iv = new byte[getBlockSizeBytes()];
            cipherBytes = new byte[data.length - iv.length];
            Utils.split(data, iv, cipherBytes);
            aps = makeParameterSpec(iv);
        }
        
        try {
            synchronized(cipher) {
                if (aps!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, key, aps, getSecureRandom());
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key, getSecureRandom());
                }
                
                return cipher.doFinal(cipherBytes);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException  ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_DECRYPT_MSG_FMT,
                getTransformation(),
                ex.getLocalizedMessage()),ex);
        }
    }
    
    /**
     * Key object used to encrypt and decrypt messages
     * 
     * @return internal Key object
     * @throws CryptoException 
     * @see Key
     */
    public Key getKey() throws CryptoException {
        return key;
    }
    
    /**
     * Key encoded as an array of bytes
     * 
     * @return Key in bytes
     */
    public byte[] getKeyEncoded() {
        return key.getEncoded();
    }
}