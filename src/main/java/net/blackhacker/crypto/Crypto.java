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
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *  Abstract base class for both symmetric and asymmetric encryption algorithms
 * 
 *  @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public abstract class Crypto implements Encryptor, Decryptor {
    
    final private Transformation transformation;
    
    /**
     * Cipher
     */
    final private Cipher cipher;
    
    /**
     * SecureRandom
     */
    final private SecureRandom secureRandom = new SecureRandom();
    
    //final private AlgorithmParameterSpec algorithmParameterSpec;

    private int iterationCount = 100;
    private byte[] salt;
    private byte[] iv;
    
    
    /**
     * Constructor
     * 
     * @param transformation
     * @param params
     * @throws CryptoException
     */
    protected  Crypto(final Transformation transformation, Object... params) throws CryptoException {
        Validator.notNull(transformation, "transformation");
        this.transformation = transformation;
        
        try {
            cipher = Cipher.getInstance(transformation.getAlgorithmString());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            String msg = String.format(
                    "Couldn't generate cipher for %s : %s", 
                    transformation.getAlgorithmString(),
                    ex.getLocalizedMessage());
            throw new CryptoException(msg, ex);
        }
    }
    
    
    /*  Getters and Setters */
    
    
    /**
     * 
     * @return Cipher
     * @see Cipher
     */
    final public Cipher getCipher()  {
        return cipher;
    }
    
    /**
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
     * @return
     * @see Transformation
     */
    final public Transformation getTransformation() {
        return transformation;
    }

    /**
     *
     * @return
     */
    public int getIterationCount(){
        return iterationCount;
    }
    
    /**
     *
     * @param iterationCount
     */
    final public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
    }

    /**
     *
     * @return
     */
    final public byte[] getIV(){
        if (iv==null)
            return null;
        return Arrays.copyOf(iv, iv.length);
    }

    final public void setIV(final byte[] iv) {
        Validator.notNull(iv, "iv");
        this.iv = Arrays.copyOf(iv, iv.length);
    }
    
    /**
     *
     * @return
     */
    final public byte[] generateIV() {
        iv = transformation.generateIV(secureRandom);
        return getIV();
    }
    
    /**
     *
     * @return
     */
    final public byte[] getSalt() {
        if (salt==null)
            return null;
        return Arrays.copyOf(salt, salt.length);
    }
    
    final public void setSalt(byte[] salt) {
        this.salt = Arrays.copyOf(salt, salt.length);
    }
    
    final public byte[] generateSalt() {
        salt = new byte[ transformation.getBlockSizeBytes()];
        secureRandom.nextBytes(salt);
        return getSalt();
    }
    
    protected AlgorithmParameterSpec processParameters(Object[] parameters) {
        AlgorithmParameterSpec aps = null;
        if (transformation.hasIV()) {
            byte[] iv = null;
            if (parameters != null && parameters.length > 0) {
                for(Object parameter : parameters) {
                    if (parameter.getClass().equals(byte[].class)) {
                        setIV((byte[])parameter);
                        iv = getIV();
                        break;
                    }
                }
            }
            
            if (iv==null){
                iv = generateIV();
            }
            aps = new IvParameterSpec(iv);
            
        } else if (transformation.isPBE()) {
            if (parameters!=null && parameters.length > 0) {
                for(Object parameter : parameters) {
                    if (parameter.getClass().equals(Integer.class)){
                        iterationCount = (Integer)parameter;
                        
                    } else if (parameter.getClass().equals(byte[].class)) {
                        setSalt((byte[])parameter);
                    }
                }
            }
            
            if (salt == null) {
                generateSalt();
            }
            aps = new PBEParameterSpec(salt, iterationCount);
        }
        
        return aps;
    }    

    public boolean hasIV() {
        return transformation.hasIV();
    }

    public boolean isPBE() {
        return transformation.isPBE();
    }

    public boolean isAsymetric() {
        return transformation.isAsymetric();
    }
    
    
}