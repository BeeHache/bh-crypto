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

/**
 * Implemented by all classes that decrypt encrypted bytes
 * 
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public interface Decryptor {
    
    /**
     * Decrypts an encrypted byte array
     * 
     * @param data encrypted byte array
     * @return clear version of data
     * @throws CryptoException 
     */
    default byte[] decrypt(final byte[] data) throws CryptoException {
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
    default byte[] decrypt(final byte[] data, int offset, int length) throws CryptoException {
        Validator.notNull(data, "data");
        Validator.gte(offset, 0, "offset");
        Validator.lte(length, data.length, "length");
        return _decrypt(data, offset, length);
    }
    
    public byte[] _decrypt(final byte[] data, int offset, int length) throws CryptoException;

}
