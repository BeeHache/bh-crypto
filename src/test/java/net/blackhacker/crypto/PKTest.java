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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import net.blackhacker.crypto.algorithm.AsymetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.Padding;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

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
    
    static private SecureRandom secureRandom;
    
    public PKTest(Transformation t) {
        transformation = t;
    }
    
    @Parameterized.Parameters
    public static Collection<Transformation[]> data() throws CryptoException {
        List<Transformation[]> l = new ArrayList<>(Arrays.asList(
            new Transformation[][] {
                { new Transformation(AsymetricAlgorithm.RSA1024, Mode.ECB, Padding.PKCS1Padding) },
                { new Transformation(AsymetricAlgorithm.RSA2048, Mode.ECB, Padding.PKCS1Padding) },
                
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
    public void setupTest() throws CryptoException {
        friend = new PK(transformation);
        me = new PK(transformation, friend.getPublicKeyEncoded());
        foe = new PK(transformation);
        message = new byte[transformation.getBlockSizeBytes()];
        secureRandom.nextBytes(message);
    }

    @Test
    public void encryptDecryptTest() throws CryptoException {
        byte[] iv = null;
        byte[] clearbytes2;
        String algorithm = me.getTransformation().toString();
        boolean hasIV = me.hasIV();
        Object[] params = null;
        
        byte[] friendCipherBytes = friend.encrypt(message);
        assertNotNull(algorithm + ":friend.encrypt: failed", friendCipherBytes);
        
        if (hasIV) {
            iv = friend.getIV();
            params = new Object[] { iv };
        }
        
        byte[] friendClearBytes = friend.decrypt(friendCipherBytes, params);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt itself", 
                message, friendClearBytes);
        
        byte[] meCipherBytes = me.encrypt(message, params);
        assertNotNull(algorithm + ":me.encrypt: failed", meCipherBytes);

        friendClearBytes = friend.decrypt(meCipherBytes, params);
        assertNotNull(algorithm + ":friend.decrypt: failed", friendClearBytes);
        assertArrayEquals(algorithm + ":friend doesn't decrypt me", 
                message, friendClearBytes);
        
        try {
            clearbytes2 = foe.decrypt(friendCipherBytes, params);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted friend's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch(CryptoException e) {
            // this is good. foes shouldn't be able to decrypt friend bytes
        }
        
        try {
            clearbytes2 = foe.decrypt(meCipherBytes, params);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted me's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch (CryptoException e) {
            // 
        }
    }
}
