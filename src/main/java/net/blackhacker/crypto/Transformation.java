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

import net.blackhacker.crypto.algorithm.Padding;
import net.blackhacker.crypto.algorithm.SymmetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import net.blackhacker.crypto.algorithm.AsymmetricAlgorithm;
import java.lang.reflect.InvocationTargetException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Holds the information about the Algorithm, mode and Padding used to initialize
 * a cipher
 * 
 * @author Benjamin King 
 */
public class Transformation {
        
    final private SymmetricAlgorithm symmetricAlgorithm;
    final private AsymmetricAlgorithm asymmetricAlgorithm;
    final private DigestAlgorithm digestAlgorithm;
    final private Mode mode;
    final private Padding padding;
        
    private Transformation(
            DigestAlgorithm digestAlgorithm,
            SymmetricAlgorithm symmetricAlgorithm,
            AsymmetricAlgorithm asymmetricAlgorithm,
            Mode mode, 
            Padding padding, 
            boolean isPBE) {
        this.digestAlgorithm = digestAlgorithm;
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.asymmetricAlgorithm = asymmetricAlgorithm;
        this.mode = mode;
        this.padding = padding;
    }
        
    public Transformation(final SymmetricAlgorithm encryptionAlgorithm, final Mode mode) {
        this(null, encryptionAlgorithm, null, mode, Padding.PKCS5Padding, false);
    }
        
    public Transformation(final DigestAlgorithm digestAlgorithm, final SymmetricAlgorithm symetricAlgorithm) {
        this(digestAlgorithm, symetricAlgorithm, null, null, null, true);
    }
        
    public Transformation(final AsymmetricAlgorithm asymetricAlgorithm, final Mode mode) {
        this(null, null, asymetricAlgorithm, mode, Padding.PKCS5Padding, false);
    }
        
    public Transformation(final AsymmetricAlgorithm asymetricAlgorithm, final Mode mode, final Padding padding) {
        this(null, null, asymetricAlgorithm, mode, padding, false);
    }
        
    /**
     * Block size in bits
     * 
     * @return block size in bits
     */
    public int getBlockSize() {
        return isSymmetric()
            ? symmetricAlgorithm.getBlockSize()
            : asymmetricAlgorithm.getBlockSize();
    }
        
    public int getKeySize() {
        return isSymmetric()
            ? -1
            : asymmetricAlgorithm.getKeySize();
    }
        
    /**
     * Block size in bytes
     * 
     * @return block size in bytes
     */
    public int getBlockSizeBytes() {
        return (int) Math.ceil((double)getBlockSize() / 8.0);
    }

    /**
     * Returns true if the mode uses an Initialization Vector (IV)
     * 
     * @return true if the mode uses an IV
     */
    public boolean hasIV() {
        return mode!= null && mode.hasIV();
    }
        
    /**
     * Returns true if this Transformation describes a Password Based Encryption
     * (PBE)
     * 
     * @return true if this Transformation describes a PBE
     */
    final public boolean isPBE() {
        return digestAlgorithm !=null;
    }
        
    /**
     * Returns true if this Transformation describes an Asymmetric Algorithm
     * 
     * @return true is THIS is asymmetric
     */
    final public boolean isAsymmetric() {
        return asymmetricAlgorithm != null;
    }
        
    /**
     * Returns true is this is Transformation describes a Symmetric 
     * @return
     */
    final public boolean isSymmetric() {
        return symmetricAlgorithm != null;
    }
        
    final public SymmetricAlgorithm getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }
        
    final public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public KeySpec makeKeySpec(Object... params) throws CryptoException {
        if (isSymmetric())
            return symmetricAlgorithm.makeKeySpec(params);
            
        throw new CryptoException(Strings.NOT_SYMETRIC_MSG);
    }

    public KeySpec makePublicKeySpec(Object... params) throws CryptoException{
        if (isAsymmetric())
            return asymmetricAlgorithm.makePublicKeySpec(params);
            
        throw new CryptoException(Strings.NOT_ASYMETRIC_MSG);
    }
        
    public KeySpec makePrivateKeySpec(Object... params) throws CryptoException {
        if (isAsymmetric())
            return asymmetricAlgorithm.makePrivateKeySpec(params);
            
        throw new CryptoException(Strings.NOT_ASYMETRIC_MSG);
    }
        
    /**
     * Builds AlgorithmParameterSpec based on the this Transformation object and 
     *  the parameters passed in
     * 
     * @param params
     * @return AlgorithmParameterSpec
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public AlgorithmParameterSpec makeParameterSpec(Object...params) throws CryptoException {
        try {
            if (params.length==0) {
                return null;

            } else if (isPBE()) {
                return PBEParameterSpec.class
                    .getConstructor(byte[].class, int.class)
                    .newInstance(params);

            } else if (isSymmetric()) {
                return symmetricAlgorithm
                        .getAlgorParamSpecClass()
                        .getConstructor(getClasses(params))
                        .newInstance(params);
            }
        } catch (NoSuchMethodException | SecurityException |
                    InstantiationException | IllegalAccessException | 
                    IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't build parameterspec :" + ex.getLocalizedMessage(), ex);
        }
        
        throw new CryptoException("Unsupported parameters");
    }
        
    static private Class<?>[] getClasses(Object[] objs) {
        Class<?>[] classes = new Class<?>[objs.length]; 
        for(int i = 0; i< objs.length; i++) {
            classes[i] = objs[i].getClass();
        }
        
        return classes;
    }
        
    @Override
    public String toString() {
        if(isPBE())
            return String.format("PBEWith%sAnd%s", 
                digestAlgorithm.name(), 
                symmetricAlgorithm.getPBEName());
            
        else if (isSymmetric())
            return String.format("%s/%s/%s", 
                symmetricAlgorithm, 
                mode, 
                padding);
        else
            return String.format("%s/%s/%s", 
                asymmetricAlgorithm, 
                mode, 
                padding);
    }
        
    /**
     *  Algorithm String
     * 
     * @return Algorithm String
     */
    public String getAlgorithmString() {
        if (isPBE())
            return String.format("PBEWith%sAnd%s", 
                digestAlgorithm.name(), 
                symmetricAlgorithm.getPBEName());
        else if (isSymmetric())
            return symmetricAlgorithm.toString();
        else
            return asymmetricAlgorithm.toString();
        }
    }
