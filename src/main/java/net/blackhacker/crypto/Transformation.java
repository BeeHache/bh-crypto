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
import java.security.SecureRandom;
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
        
        final public boolean isAsymetric() {
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
            return symetricAlgorithm!=null
                    ? symetricAlgorithm.makeKeySpec(key)
                    : asymetricAlgorithm.makePublicKeySpec(key);
        }
        
        public AlgorithmParameterSpec makeParameterSpec(Object...params) throws CryptoException {
            if (isPBE) {
                Validator.isTrue(params.length==2, "");
                return new PBEParameterSpec((byte[])params[0], (int)params[1]);
            } else if (symetricAlgorithm != null) {
                Validator.isTrue(params.length==1, "");
                return symetricAlgorithm.makeParameterSpec((byte[])params[0]);
            } else if (params.length>1){
                Validator.isA(params[0], byte[].class, "params[0]");
                Validator.isA(params[1], int.class, "params[1] should be an int");
                return asymetricAlgorithm.makeParameterSpec((byte[])params[0], (int)params[1]);
            } else {
                Validator.isA(params[0], byte[].class, "params[0]");
                return asymetricAlgorithm.makeParameterSpec((byte[])params[0]);
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
