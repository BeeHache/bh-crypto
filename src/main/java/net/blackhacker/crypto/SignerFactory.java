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

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class SignerFactory {

    /**
     *
     * @return SignerBase Object
     * @throws net.blackhacker.crypto.SignerException
     */
    static public Signer newSignerDESwithMD5() throws SignerException {
        try {
            SK sk = EncryptorFactory.newEncryptorDESWithECB();
            return new SignerBase(sk, sk,DigesterFactory.newDigesterMD5());
        } catch(CryptoException | DigesterException e) {
            throw new SignerException("Coun't init DES Signer",e);
        }
    }

    /**
     *
     * @param passphrase
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param digestAlgorithm
     * @return
     * @throws net.blackhacker.crypto.SignerException
     *
    static public Signer newInstancePBE(String passphrase, String cipherAlgorithm, String keyAlgorithm, String digestAlgorithm) 
            throws SignerException {
        try {
            return new Signer(new PBE(cipherAlgorithm, keyAlgorithm, passphrase), new MD(digestAlgorithm));
        } catch (CryptoException e) {
            throw new SignerException("Coun't init PBE Signer",e);
        }
    }
    */ 
    
    /**
     *
     * @return SignerBase object
     * @throws net.blackhacker.crypto.SignerException
     */
    static public Signer newSignerRSAWithMD5() throws SignerException  {
        
        try {
            PK pk = EncryptorFactory.newEncryptorRSA();
            return new SignerBase(pk,pk, DigesterFactory.newDigesterMD5());
        } catch(CryptoException | DigesterException e) {
            throw new SignerException("Coun't init RSA Signer",e);
        }
    }    
}