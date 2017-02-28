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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.locks.StampedLock;
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

    private int iterationCount = 100;
    private byte[] salt;
    private byte[] iv;
    
    
    private final StampedLock saltLock = new StampedLock();
    private final StampedLock ivLock = new StampedLock();
    
    /**
     * Constructor
     * 
     * @param transformation
     * @param params
     * @throws CryptoException
     */
    protected  Crypto(final Transformation transformation, final Object... params) throws CryptoException {
        Validator.notNull(transformation, "transformation");
        Validator.notNull(params, "params");
        this.transformation = transformation;
        
        try {
            String as = transformation.toString();
            cipher = Cipher.getInstance(as);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            String msg = String.format(
                    Strings.COULDNT_CREATE_CIPHER, 
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
     * Iteration count
     * 
     * @return iteration count
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
     * returns a byte array containing the Initialization Vector(IV)
     * It should be noted that this is a copy of the arrays that is maintained
     * internally
     * 
     * @return iv
     */
    final public byte[] getIV(){
        long stamp = ivLock.readLock();
        try {
        if (iv==null)
            return null;
        return Arrays.copyOf(iv, iv.length);
        } finally {
            ivLock.unlock(stamp);
        }
    }

    /**
     * sets the value of the Initialization Vector
     * 
     * @param iv a byte array
     */
    final public void setIV(final byte[] iv) {
        long stamp = ivLock.writeLock();
        try {
            Validator.notNull(iv, "iv");
            this.iv = Arrays.copyOf(iv, iv.length);
        } finally {
            ivLock.unlock(stamp);
        }
    }
    
    /**
     * Generates a new Initialization Vector (IV) and stores it internally
     * 
     * @return new IV in the form a byte array
     */
    final public byte[] generateIV() {
        setIV(transformation.generateIV(secureRandom));
        return getIV();
    }
    
    /**
     *  Salt
     * 
     * @return salt in the form of a byte array
     */
    final public byte[] getSalt() {
        long stamp = saltLock.readLock();
        try {
            if (salt==null)
                return null;
            return Arrays.copyOf(salt, salt.length);
        } finally {
            saltLock.unlock(stamp);
        }
    }
    
    final public void setSalt(byte[] salt) {
        long stamp = saltLock.writeLock();
        try {
            this.salt = Arrays.copyOf(salt, salt.length);
        } finally {
            saltLock.unlock(stamp);
        }
    }
    
    final public byte[] generateSalt() {
        byte[] s  = new byte[ transformation.getBlockSizeBytes()];
        secureRandom.nextBytes(s);
        setSalt(s);
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

    /**
     *
     * @return returns true if this is s
     */
    public boolean hasIV() {
        return transformation.hasIV();
    }

    /**
     *
     * @return true if this is a PBE
     */
    public boolean isPBE() {
        return transformation.isPBE();
    }

    /**
     * Returns true if this object represents an asymetric algorithm
     * 
     * @return true is the object represents an asymetric algorithm
     */
    public boolean isAsymetric() {
        return transformation.isAsymetric();
    }
    
    
}