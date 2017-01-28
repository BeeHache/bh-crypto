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

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import net.blackhacker.crypto.Crypto.Algorithm;
import net.blackhacker.crypto.Crypto.Mode;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author ben
 */
@RunWith(Parameterized.class)
public class SKTest {
    
    final Transformation transformation;
    
    private SK me;
    private SK friend;
    private SK foe;
    
    static private String passphrase;
    static private byte[] message = new byte[245];  //245 is the largest data RSA encrypts
    
    public SKTest(Transformation t) {
        transformation = t;
    }
    
    @Parameterized.Parameters
    public static Collection<Transformation[]> data() throws CryptoException {
        
        List<Transformation[]> l = new ArrayList<>(Arrays.asList(
            new Transformation[][] {
                { new Transformation(Algorithm.DES, Mode.ECB) },
                { new Transformation(Algorithm.DES, Mode.CBC) },
                { new Transformation(Algorithm.DES, Mode.CFB) },
                { new Transformation(Algorithm.DES, Mode.OFB) },
                
                { new Transformation(Algorithm.DESede, Mode.ECB) },
                { new Transformation(Algorithm.DESede, Mode.CBC) },
                { new Transformation(Algorithm.DESede, Mode.CFB) },
                { new Transformation(Algorithm.DESede, Mode.OFB) },
                
                { new Transformation(Algorithm.AES, Mode.ECB) },
                { new Transformation(Algorithm.AES, Mode.CBC) },
                { new Transformation(Algorithm.AES, Mode.CFB) },
                { new Transformation(Algorithm.AES, Mode.OFB) },
                { new Transformation(Algorithm.AES, Mode.CTR) },
            }
        ));
        
        return l;
    }
    
    @Rule
    public ErrorCollector collector= new ErrorCollector();

    @BeforeClass
    static public void setupClass() throws CryptoException {
        SecureRandom sr = new SecureRandom();
        passphrase = "The quickbown fox jumped over the lazy dog.";
        sr.nextBytes(message);
        //message = "A far far better thing I do than I have ever done before.".getBytes(StandardCharsets.UTF_8);
        Security.insertProviderAt(new BouncyCastleProvider(),1);
    }

    
    @Before
    public void setup() throws CryptoException, InvalidKeyException {
        friend = new SK(transformation, null);
        foe = new SK(transformation, null);
        me = new SK(transformation, null, friend.getKeyEncoded());
    }
    
    @Test
    public void encryptDecryptTest() throws CryptoException {
        String algorithm = me.getAlgorithm();
        
        byte[] friendCipherBytes = friend.encrypt(message);
        assertNotNull(algorithm + ":friend.encrypt: failed", friendCipherBytes);
        
        byte[] friendClearBytes = friend.decrypt(friendCipherBytes);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt itself", 
                message, friendClearBytes);
        
        byte[] meCipherBytes = me.encrypt(message);
        assertNotNull(algorithm + ":me.encrypt: failed", meCipherBytes); 
        
        byte[] meClearBytes = me.decrypt(meCipherBytes);
        assertNotNull(algorithm + ":me.encrypt: failed", meClearBytes);
        assertArrayEquals(algorithm + ":me doesn't decrypt itself",
                meClearBytes, message);

        friendClearBytes = friend.decrypt(meCipherBytes);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt me", 
                message, friendClearBytes);
        
        meClearBytes = me.decrypt(friendCipherBytes);
        assertNotNull(algorithm + ":me.decrypt: failed", meClearBytes);
        assertArrayEquals(algorithm + ":me doesn't decrypt friend", 
                message, friendClearBytes);
        
        try {
            byte[] clearbytes2 = foe.decrypt(friendCipherBytes);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted friend's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch(CryptoException e) {
            // this is good. foes shouldn't be able to decrypt friend bytes
        }
        
        try {
            byte[] clearbytes2 = foe.decrypt(meCipherBytes);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted me's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch (CryptoException e) {
            // 
        }
    }
}
