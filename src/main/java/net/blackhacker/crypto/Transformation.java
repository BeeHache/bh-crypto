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

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

/**
 *
 * @author ben
 */
    public class Transformation implements CipherAlgorithm {
        final Crypto.Algorithm algorithm;
        final Crypto.Mode mode;
        final Crypto.Padding padding;
        
        Transformation(Crypto.Algorithm algorithm, Crypto.Mode mode, Crypto.Padding padding) {
            this.algorithm = algorithm;
            this.mode = mode;
            this.padding = padding;
        }

        Transformation(Crypto.Algorithm algorithm, Crypto.Mode mode) {
            this.algorithm = algorithm;
            this.mode = mode;
            this.padding = Crypto.Padding.PKCS5Padding;
        }
        
        public int getBlockSize() {
            return algorithm.blockSize();
        }
        
        public int getBlockSizeBytes() {
            return (int) Math.ceil((double)getBlockSize() / 8.0);
        }

        public boolean hasIV() {
            return mode.hasIV();
        }
        
        public byte[] readIV(InputStream is ) throws IOException {
            byte[] iv = new byte[getBlockSizeBytes()];
            is.read(iv);
            return iv;
        }
        
        public byte[] getIV(SecureRandom secureRandom) {
            byte[] array = new byte[ getBlockSizeBytes()];
            secureRandom.nextBytes(array);
            return array;            
        }
        
        public Crypto.Algorithm getAlgorithm() {
            return algorithm;
        }
        
        @Override
        public String toString() {
            return new StringBuilder()
                .append(algorithm).append("/")
                .append(mode).append("/")
                .append(padding).toString();
        }
    }
