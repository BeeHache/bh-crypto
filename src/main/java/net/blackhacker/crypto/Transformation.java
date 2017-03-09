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
import net.blackhacker.crypto.algorithm.SymetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import net.blackhacker.crypto.algorithm.AsymetricAlgorithm;
import java.io.IOException;
import java.io.InputStream;
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
        
        final private SymetricAlgorithm symetricAlgorithm;
        final private AsymetricAlgorithm asymetricAlgorithm;
        final private DigestAlgorithm digestAlgorithm;
        final private Mode mode;
        final private Padding padding;
        
        private Transformation(
                DigestAlgorithm digestAlgorithm,
                SymetricAlgorithm symetricAlgorithm,
                AsymetricAlgorithm asymetricAlgorithm,
                Mode mode, 
                Padding padding, 
                boolean isPBE) {
            this.digestAlgorithm = digestAlgorithm;
            this.symetricAlgorithm = symetricAlgorithm;
            this.asymetricAlgorithm = asymetricAlgorithm;
            this.mode = mode;
            this.padding = padding;
        }

        public Transformation(final SymetricAlgorithm encryptionAlgorithm, final Mode mode, final Padding padding) {
            this(null, encryptionAlgorithm, null, mode, padding, false);
        }
        
        public Transformation(final SymetricAlgorithm encryptionAlgorithm, final Mode mode) {
            this(null, encryptionAlgorithm, null, mode, Padding.PKCS5Padding, false);
        }
        
        public Transformation(final DigestAlgorithm digestAlgorithm, final SymetricAlgorithm symetricAlgorithm) {
            this(digestAlgorithm, symetricAlgorithm, null, null, null, true);
        }
        
        public Transformation(final AsymetricAlgorithm asymetricAlgorithm, final Mode mode) {
            this(null, null, asymetricAlgorithm, mode, Padding.PKCS5Padding, false);
        }
        
        public Transformation(final AsymetricAlgorithm asymetricAlgorithm, final Mode mode, final Padding padding) {
            this(null, null, asymetricAlgorithm, mode, padding, false);
        }
        
        public int getBlockSize() {
            return isSymetric()
                    ? symetricAlgorithm.getBlockSize()
                    : asymetricAlgorithm.getBlockSize();
        }
        
        public int getKeySize() {
            return isSymetric()
                    ? -1
                    : asymetricAlgorithm.getKeySize();
        }
        
        public int getBlockSizeBytes() {
            return (int) Math.ceil((double)getBlockSize() / 8.0);
        }

        public boolean hasIV() {
            return mode!= null && mode.hasIV();
        }
        
        final public boolean isPBE() {
            return digestAlgorithm !=null;
        }
        
        final public boolean isAsymetric() {
            return asymetricAlgorithm != null;
        }
        
        final public boolean isSymetric() {
            return symetricAlgorithm != null;
        }
        
        final public SymetricAlgorithm getSymetricAlgorithm() {
            return symetricAlgorithm;
        }
        
        final public DigestAlgorithm getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public KeySpec makeKeySpec(Object... params) throws CryptoException {
            if (isSymetric())
                return symetricAlgorithm.makeKeySpec(params);
            
            throw new CryptoException(Strings.NOT_SYMETRIC_MSG);
        }

        public KeySpec makePublicKeySpec(Object... params) throws CryptoException{
            if (isAsymetric())
                return asymetricAlgorithm.makePublicKeySpec(params);
            
            throw new CryptoException(Strings.NOT_ASYMETRIC_MSG);
        }
        
        public KeySpec makePrivateKeySpec(Object... params) throws CryptoException {
            if (isAsymetric())
                return asymetricAlgorithm.makePrivateKeySpec(params);
            
            throw new CryptoException(Strings.NOT_ASYMETRIC_MSG);
        }
        
        public AlgorithmParameterSpec makeParameterSpec(Object...params) throws CryptoException {
            try {
                if (params.length==0) {
                    return null;

                } else if (isPBE()) {
                    return PBEParameterSpec.class
                        .getConstructor(byte[].class, int.class)
                        .newInstance(params);

                } else if (isSymetric()) {
                    return symetricAlgorithm
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
                        symetricAlgorithm.getPBEName());
            
            else if (isSymetric())
                return String.format("%s/%s/%s", 
                        symetricAlgorithm, 
                        mode, 
                        padding);
            else
                return String.format("%s/%s/%s", 
                        asymetricAlgorithm, 
                        mode, 
                        padding);
        }
        
        public String getAlgorithmString() {
            if (isPBE())
                return String.format("PBEWith%sAnd%s", 
                    digestAlgorithm.name(), 
                    symetricAlgorithm.getPBEName());
            else if (isSymetric())
                return symetricAlgorithm.toString();
            else
                return asymetricAlgorithm.toString();
        }
    }
