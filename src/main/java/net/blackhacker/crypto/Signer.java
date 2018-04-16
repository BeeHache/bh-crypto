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

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public abstract class Signer {

    /**
     * Signs given object
     * 
     * @param data bytes that should be signed
     * @return signature
     * @throws SignerException
     */
    final public byte[] sign(final byte[] data) throws SignerException {
        Validator.notNull(data, "data");
        return signImpl(data, 0, data.length);
    }
    /**
     * 
     * @param data
     * @param pos
     * @param len
     * @return
     * @throws SignerException 
     */
    final public byte[] sign(final byte[] data, int pos, int len) throws SignerException {
        Validator.notNull(data, "data");
        Validator.isPositive(pos, "pos");
        Validator.isLessThan(len, data.length-pos, "data");
        return signImpl(data, pos, len);
    }
    
    protected abstract byte[] signImpl(final byte[] data, int pos, int len) throws SignerException;

}
