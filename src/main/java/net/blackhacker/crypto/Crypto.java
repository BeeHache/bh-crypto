/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2018 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import net.blackhacker.crypto.utils.Validator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 *  Abstract base class for both symmetric and asymmetric encryption algorithms
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class Crypto {
    
    final private Transformation transformation;
        
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
     * @param transformation Transformation object
     * @throws CryptoException
     */
    public  Crypto(Transformation transformation) throws CryptoException {
        this.transformation = Validator.notNull(transformation, "transformation");
        
        try {
            cipher = Cipher.getInstance(transformation.toString());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            String msg = String.format(Strings.COULDNT_CREATE_CIPHER_MSG_FMT, 
                    transformation.getAlgorithmString(),
                    ex.getLocalizedMessage());
            throw new CryptoException(msg, ex);
        }
    }
    
    
    /*  Getters and Setters */
    
    
    /**
     * The internal Cipher object
     * 
     * @return Cipher
     * @see Cipher
     */
    final public Cipher getCipher()  {
        return cipher;
    }
    
    /**
     * The internal SecureRandom
     * 
     * @return SecureRandom object
     * @see SecureRandom
     */
    final public SecureRandom getSecureRandom() {
        return secureRandom;
    }    
    
    /**
     * Transformation
     * 
     * @return internal Transformation object
     * @see Transformation
     */
    final public Transformation getTransformation() {
        return transformation;
    }
    
    /**
     * Generates a new Initialization Vector (IV)
     * 
     * @return new IV in the form a byte target
     */
    final public byte[] generateIV() {        
        byte[] iv = new byte[ transformation.getBlockSizeBytes()];
        secureRandom.nextBytes(iv);
        return iv;
    }
    
    /**
     * Randomly generates salt bytes
     * 
     * @return salt
     */
    final public byte[] generateSalt() {
        byte[] salt = new byte[transformation.getSaltSizeBytes()];
        secureRandom.nextBytes(salt);
        return salt;
    }
    
    /**
     *  Builds {@link AlgorithmParameterSpec} based on the Transformation and the
     * parameters are passed in
     * 
     * @param parameters inputs to parameterspec
     * @return AlgorithmParameterSpec
     * @throws CryptoException errors
     * @see AlgorithmParameterSpec
     */
    final public AlgorithmParameterSpec makeParameterSpec(Object... parameters) 
            throws CryptoException {
        return transformation.makeParameterSpec(parameters);
    }
    
    /**
     *
     * @param parameters inputs
     * @return KeySpec object
     * @throws CryptoException errors
     * @see KeySpec
     */
    final public KeySpec makeKeySpec(Object... parameters)
            throws CryptoException {
        return transformation.makeKeySpec(parameters);
    }

    /**
     * Returns the block size for the algorithm described in the internal 
     * Transformation
     * 
     * @return block size
     */
    final public int getBlockSizeBytes(){
        return transformation.getBlockSizeBytes();
    }

    /**
     * Returns true if the Mode uses an Initialization Vector (IV), otherwise 
     * false
     * 
     * @return true if the Mode uses an IV, otherwise false
     */
    public boolean hasIV() {
        return transformation.hasIV();
    }

    /**
     * Returns true if the Transformation describes a Password Based Encryption
     * (PBE)
     * 
     * @return true if this is a PBE
     */
    public boolean isPBE() {
        return transformation.isPBE();
    }

    /**
     * Returns true if this object represents an asymmetric algorithm
     * 
     * @return true is the object represents an asymmetric algorithm
     */
    public boolean isAsymetric() {
        return transformation.isAsymmetric();
    }
}