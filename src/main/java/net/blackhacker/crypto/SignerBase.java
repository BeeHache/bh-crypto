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

import java.util.Arrays;

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class SignerBase implements Signer{
    final private Encryptor encryptor;
    final private Digester md;
    
    protected SignerBase(Encryptor crypto, Digester md) {
        this.encryptor = crypto;
        this.md = md;
    }


    
    /**
     * signs an array of bytes
     * 
     * @param data
     * @return signature for given data
     * @throws net.blackhacker.crypto.SignerException
     */
    @Override
    public byte[] sign(byte[] data) throws SignerException {
        try {
            byte[] digest = md.digest(data);
            return encryptor.encrypt(digest);
        } catch (CryptoException ex) {
            throw new SignerException("Couldn't sign data",ex);
        }
    }
    
    /**
     * verifies signature for a given array of bytes
     * 
     * @param data
     * @param signature
     * @return true 
     * @throws net.blackhacker.crypto.SignerException 
     */
    @Override
    public boolean verify(byte[] data, byte[] signature) throws SignerException {
        try {
            byte[] d = md.digest(data);
            byte[] c = encryptor.decrypt(signature);
            return Arrays.equals(d, c);
        } catch(CryptoException ex) {
            return false;
        } catch (Exception ex) {
            throw new SignerException("Couldn't verify signature",ex);
        }
    }
}
