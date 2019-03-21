/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2019 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import net.blackhacker.crypto.utils.Utils;
import net.blackhacker.crypto.utils.Validator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
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
public class SK extends Crypto implements Encryptor, Decryptor {
    final private Key key;
        
    protected SK(Transformation transformation, Object... parameters) throws CryptoException{
        super(transformation);
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
     * Encrypts array of bytes
     * 
     * @param clearBytes
     * @return encrypted version of clearBytes
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] clearBytes) throws CryptoException {
        return _encrypt(Validator.notNull(clearBytes, "clearBytes"), 0, clearBytes.length);
    }
    
    /**
     * 
     * @param clearBytes
     * @param offset
     * @param length
     * @return
     * @throws CryptoException 
     */
    @Override
    public byte[] encrypt(final byte[] clearBytes, int offset, int length) throws CryptoException {
        return _encrypt(
                Validator.notNull(clearBytes, "clearBytes"),
                Validator.gte(offset, 0, "offset"), 
                Validator.lte(length, clearBytes.length, "length"));
    }
    
    /**
     * encrypts byte arrays
     * 
     * @param clearBytes
     * @param offset
     * @param length
     * @return encrypted version data
     * @throws CryptoException
     */
    private byte[] _encrypt(final byte[] clearBytes, int offset, int length) throws CryptoException {
        Cipher cipher = getCipher();
        AlgorithmParameterSpec aps=null;
        byte[] iv = null;
        byte[] salt = null;
        byte[] iterationCountBytes = null;
        
        if (isPBE()) {
            salt = generateSalt();
            iterationCountBytes = Utils.toBytes(5000 + getSecureRandom().nextInt(1000));
            aps = makeParameterSpec(salt, Utils.toInt(iterationCountBytes));
            
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
                
                byte[] cipherbytes = cipher.doFinal(clearBytes,offset, length);
                
                return Utils.concat(salt, iterationCountBytes, iv, cipherbytes);
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
        return _decrypt(data, 0, data.length);
    }
    
    /**
     * 
     * @param data
     * @param offset
     * @param length
     * @return
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data, int offset, int length) throws CryptoException {
        Validator.notNull(data, "data");
        Validator.gte(offset, 0, "offset");
        Validator.lte(length, data.length, "length");
        return _decrypt(data, offset, length);
    }
     
    
    private byte[] _decrypt(final byte[] data, int offset, int length) throws CryptoException {
        
        Cipher cipher = getCipher();
        AlgorithmParameterSpec aps = null;
        byte[] iv = null;
        byte[] salt = null;
        byte[] iterationCountBytes = null;
        byte[] cipherBytes = Arrays.copyOfRange(data, offset, offset+length);
        
        if (isPBE()){
            iterationCountBytes = new byte[Integer.BYTES];
            salt = new byte[getTransformation().getSaltSizeBytes()];
            cipherBytes = new byte[length - salt.length - iterationCountBytes.length];
            
        } else if (hasIV()) {
            iv = new byte[getBlockSizeBytes()];
            cipherBytes = new byte[length - iv.length];
        }
        
        if (iv !=null || salt!=null)
            Utils.split(Arrays.copyOfRange(data, offset, offset+length), 
                    salt, iterationCountBytes, iv, cipherBytes);
         
        
        if (salt!=null){
            aps = makeParameterSpec(salt, Utils.toInt(iterationCountBytes));
        } else if (iv!=null) {
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
        }catch(BadPaddingException ex) {
            //decryption failed
            return null;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException  ex) {
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