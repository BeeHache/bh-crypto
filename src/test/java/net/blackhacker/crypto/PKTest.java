/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2019 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import net.blackhacker.crypto.algorithm.AsymmetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.Padding;
import static org.hamcrest.MatcherAssert.assertThat;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author ben
 */
@RunWith(Parameterized.class)
public class PKTest {
    final Transformation transformation;
    
    private PK me;
    private PK friend;
    private PK foe;
    private byte[] message;
    private String algorithm;
    
    static private SecureRandom secureRandom;
    
    public PKTest(Transformation t) {
        transformation = t;
    }
    
    @Parameterized.Parameters
    public static Collection<Transformation[]> data() throws CryptoException {
        List<Transformation[]> l = new ArrayList<>(Arrays.asList(new Transformation[][] {
                { new Transformation(AsymmetricAlgorithm.RSA1024, Mode.ECB, Padding.PKCS1Padding) },
                { new Transformation(AsymmetricAlgorithm.RSA2048, Mode.ECB, Padding.PKCS1Padding) },
                
            }));
        return l;
    }

    @Rule
    public ErrorCollector collector= new ErrorCollector();

    @BeforeClass
    static public void setupClass() throws CryptoException {
        secureRandom = new SecureRandom();
    }
    
    @Before
    public void setup() throws CryptoException {
        friend = new PK(transformation, "CN=friend");
        me = new PK(transformation, friend.getPublicKeyEncoded(), "CN=me");
        foe = new PK(transformation, "CN=foe");
        message = new byte[Math.abs(secureRandom.nextInt()) % 100];
        secureRandom.nextBytes(message);
        algorithm = me.getTransformation().toString();
    }
    
    @Test
    public void encryptNotNullTest() throws CryptoException {
        byte[] friendCipherBytes = friend.encrypt(message);
        assertNotNull(algorithm + ":friend.encrypt: failed", friendCipherBytes);
    }

    @Test(expected = RuntimeException.class)
    public void encryptIncorrectLengthTest() throws CryptoException {
        friend.encrypt(message, 0, message.length + 5);
    }
    
    @Test
    public void encryptNotWeakTest() throws CryptoException {
        if(friend.hasIV()) {
            assertThat(algorithm + ":friend.encrypt: weak", 
                friend.encrypt(message), not(equalTo(friend.encrypt(message))));
        }        
    }

    @Test
    public void encryptDecryptFriend() throws CryptoException {
        byte[] friendClearBytes = friend.decrypt(friend.encrypt(message));
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt itself", 
                message, friendClearBytes);        
    }
    
    @Test(expected=CryptoException.class)
    public void foeDecrypt() throws CryptoException {
        byte[] friendCipherBytes = friend.encrypt(message);
        byte[] friendClearBytes = friend.decrypt(friendCipherBytes);
        byte[] foeClearbytes = foe.decrypt(friendCipherBytes);
            assertThat(algorithm + ":foe.decrypt: foe decrypted friend's message",
                    foeClearbytes, not(equalTo(friendClearBytes)));
    }
    
    @Test(expected = CryptoException.class)
    public void signTest() throws CryptoException {
        me.sign(message);
    }

    @Test
    public void signVerifyTest() throws CryptoException {        
        byte[] friendSig = friend.sign(message);
        assertNotNull("friendSig is NULL", friendSig);
        assertTrue("me couldn't verify friendSig", me.verify(message, friendSig));
    }
    

    @Test
    public void issueCertificateNotNullTest() throws CryptoException {
        try {
            assertNotNull("friendCert NULL", friend.issueSelfSignedCetificate());
        } catch(Exception e) {
            throw new CryptoException(e.getLocalizedMessage(),e);
        }
    }
    
    @Test
    public void issueCertificateFriendVerifyTest() throws CryptoException {
        try {
            friend.issueSelfSignedCetificate().verify(friend.getPublicKey());
        } catch(Exception e) {
            throw new CryptoException(e.getLocalizedMessage(),e);
        }
    }

    @Test(expected = CryptoException.class)
    public void issueCertificateFoeVerifyTest() throws CryptoException {
        try {
            friend.issueSelfSignedCetificate().verify(foe.getPublicKey());
        } catch(Exception e) {
            throw new CryptoException(e.getLocalizedMessage(),e);
        }
    }

    
    @Test
    public void issueSignedCertificateTest() throws CryptoException {
        
    }
    
}
