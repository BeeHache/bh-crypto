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

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

import org.junit.BeforeClass;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.junit.Assert.*;
import org.junit.Ignore;

public class SignerTest {
    final static private String digestAlgorithm ="SHA-256";
    
    static String passphrase;
    static String message;
    static AlgorithmParameterSpec pbeCipherParams;
    
    static SK[] friends;
    static SK[] foes;
    static SecretKey key;
    static Signer signerFriend;
    static Signer signerFoe;
    
    @BeforeClass
    static public void setup() throws SignerException {
        try {
            passphrase = "The quickbown fox jumped over the lazy dog.";
            message = "A far far better thing I do than I have ever done before.";
            
            Security.insertProviderAt(new BouncyCastleProvider(),1);
    
            
            friends = new SK[]{EncryptorFactory.newEncryptorDESWithECB()};
            foes = new SK[]{EncryptorFactory.newEncryptorDESWithECB()};
            signerFriend= SignerFactory.newSignerDESwithMD5();
            signerFoe = SignerFactory.newSignerDESwithMD5();
        } catch (CryptoException ex) {
            fail(ex.getMessage());
        }
    }    
    
    @Ignore
    public void signingTest() {
        try {
            byte[] data = message.getBytes();
            byte[] signature = signerFriend.sign(data);
            assertNotNull(signature);
            
            boolean verified = signerFriend.verify(data, signature);
            assertTrue(verified);
            
            verified = signerFoe.verify(data, signature);
            assertFalse(verified);
            
        } catch (SignerException ex) {
            fail(ex.getMessage());
        }
    }
}