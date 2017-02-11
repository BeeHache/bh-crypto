/*
 * The MIT License
 *
 * Copyright 2017 ben.
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

import net.blackhacker.crypto.algorithm.Padding;
import net.blackhacker.crypto.algorithm.SymetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import net.blackhacker.crypto.algorithm.AsymetricAlgorithm;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author ben
 */
    public class Transformation {
        
        final private SymetricAlgorithm symetricAlgorithm;
        final private AsymetricAlgorithm asymetricAlgorithm;
        final private DigestAlgorithm digestAlgorithm;
        final private Mode mode;
        final private Padding padding;
        final private boolean isPBE;
        
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
            this.isPBE = isPBE;
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
            return symetricAlgorithm!=null 
                    ? symetricAlgorithm.getBlockSize()
                    : asymetricAlgorithm.getBlockSize();
        }
        
        public int getKeySize() {
            return symetricAlgorithm!=null
                    ? symetricAlgorithm.getKeySize()
                    : asymetricAlgorithm.getKeySize();
        }
        
        public int getBlockSizeBytes() {
            return (int) Math.ceil((double)getBlockSize() / 8.0);
        }

        public boolean hasIV() {
            return mode!= null && mode.hasIV();
        }
        
        public boolean isPBE() {
            return isPBE;
        }
        
        public boolean isAsymetric() {
            return asymetricAlgorithm != null;
        }
        
        public byte[] readIV(InputStream is ) throws IOException {
            final byte[] iv = new byte[getBlockSizeBytes()];
            is.read(iv);
            return iv;
        }
        
        public byte[] generateIV(SecureRandom secureRandom) {
            final byte[] array = new byte[ getBlockSizeBytes()];
            secureRandom.nextBytes(array);
            return array;            
        }
        
        final public SymetricAlgorithm getSymetricAlgorithm() {
            return symetricAlgorithm;
        }
        
        final public DigestAlgorithm getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public KeySpec makeKeySpec(byte[] key) throws CryptoException {
            return symetricAlgorithm.makeKeySpec(key);
        }
        
        public AlgorithmParameterSpec makeParameterSpec(Object...params) throws CryptoException {
            if (isPBE) {
                Validator.isTrue(params.length==2, "");
                return new PBEParameterSpec((byte[])params[0], (int)params[1]);
            } else {
                Validator.isTrue(params.length==1, "");
                return symetricAlgorithm.makeParameterSpec((byte[])params[0]);
            }
        }
        
        @Override
        public String toString() {
            if(isPBE)
                return String.format("PBEWith%sAnd%s", 
                        digestAlgorithm.name(), 
                        symetricAlgorithm.getPBEName());
            else if (isAsymetric())
                return String.format("%s/%s/%s", 
                        asymetricAlgorithm, 
                        mode, 
                        padding);
            else
                return String.format("%s/%s/%s", 
                        symetricAlgorithm, 
                        mode, 
                        padding);
        }
        
        public String getAlgorithmString() {
            if (symetricAlgorithm!=null) {
                if (isPBE)
                    return String.format("PBEWith%sAnd%s", 
                        digestAlgorithm.name(), 
                        symetricAlgorithm.getPBEName());
                else
                    return symetricAlgorithm.toString();
            } else
                return asymetricAlgorithm.toString();
        }
    }
