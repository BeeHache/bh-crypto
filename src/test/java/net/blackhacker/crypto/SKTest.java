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

import net.blackhacker.crypto.algorithm.SymmetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static net.blackhacker.crypto.Utils.jce;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

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
public class SKTest {
    
    final Transformation transformation;
    
    private SK friend;
    private SK me;
    private SK foe;
    
    static private char[] passphrase;
    static private char[] foePassphrase;
    static private byte[] message;
    
    public SKTest(Transformation t) {
        transformation = t;
    }
    
    @Parameterized.Parameters
    public static Collection<Transformation[]> data() throws CryptoException {
        
        List<Transformation[]> l = new ArrayList<>(Arrays.asList(new Transformation[][] {
                { new Transformation(SymmetricAlgorithm.DES, Mode.ECB) },
                { new Transformation(SymmetricAlgorithm.DES, Mode.CBC) },
                { new Transformation(SymmetricAlgorithm.DES, Mode.CFB) },
                { new Transformation(SymmetricAlgorithm.DES, Mode.OFB) },
                
                { new Transformation(SymmetricAlgorithm.DESede, Mode.ECB) },
                { new Transformation(SymmetricAlgorithm.DESede, Mode.CBC) },
                { new Transformation(SymmetricAlgorithm.DESede, Mode.CFB) },
                { new Transformation(SymmetricAlgorithm.DESede, Mode.OFB) },
                
                { new Transformation(SymmetricAlgorithm.AES, Mode.ECB) },
                { new Transformation(SymmetricAlgorithm.AES, Mode.CBC) },
                { new Transformation(SymmetricAlgorithm.AES, Mode.CFB) },
                { new Transformation(SymmetricAlgorithm.AES, Mode.OFB) },
                { new Transformation(SymmetricAlgorithm.AES, Mode.CTR) },
                
                /*PBE */
                { new Transformation(DigestAlgorithm.MD5, SymmetricAlgorithm.DES) },
                { new Transformation(DigestAlgorithm.MD5, SymmetricAlgorithm.DESede) },
            }
        ));
        
        if (jce()) {
            l.addAll(Arrays.asList(new Transformation[][] {
                        { new Transformation(SymmetricAlgorithm.AES192, Mode.ECB) },
                        { new Transformation(SymmetricAlgorithm.AES192, Mode.CBC) },
                        { new Transformation(SymmetricAlgorithm.AES192, Mode.CFB) },
                        { new Transformation(SymmetricAlgorithm.AES192, Mode.OFB) },
                        { new Transformation(SymmetricAlgorithm.AES192, Mode.CTR) },
                        
                        /* PBE */
                        { new Transformation(DigestAlgorithm.SHA1, SymmetricAlgorithm.DESede) },
                        { new Transformation(DigestAlgorithm.SHA256, SymmetricAlgorithm.AES256) },
                        
                    }));
        }
        
        return l;
    }
    
    @Rule
    public ErrorCollector collector= new ErrorCollector();

    @BeforeClass
    static public void setupClass() throws CryptoException {
        SecureRandom sr = new SecureRandom();
        
        passphrase = new char[ sr.nextInt(30) + 1];
        for (int p = 0; p < passphrase.length; p++) {
            passphrase[p] = (char) (sr.nextInt(94) + 32);
        }

        foePassphrase = new char[ sr.nextInt(30) + 1];
        for (int p = 0; p < foePassphrase.length; p++) {
            foePassphrase[p] = (char) (sr.nextInt(94) + 32);
        }
        
        message = new byte[sr.nextInt(1024)];
        
        sr.nextBytes(message);
    }
    
    @Before
    public void setupTest() throws CryptoException {
        if (transformation.isPBE()) {
            friend = new SK(transformation, passphrase);
            me = new SK(transformation, passphrase);
            foe = new SK(transformation, foePassphrase);
            
        } else {
            friend = new SK(transformation);
            me = new SK(transformation, friend.getKeyEncoded());
            foe = new SK(transformation);
        }
    }
    
    @Test
    public void encryptDecryptTest() throws CryptoException {
        byte[] clearbytes2;
        String algorithm = me.getTransformation().toString();
        
        byte[] friendCipherBytes = friend.encrypt(message);
        assertNotNull(algorithm + ":friend.encrypt: failed", friendCipherBytes);
        
        if(friend.hasIV()){
            assertThat(algorithm + ":friend.encrypt: weak", 
                    friend.encrypt(message), not(equalTo(friendCipherBytes)));
        }
        
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
            clearbytes2 = foe.decrypt(friendCipherBytes);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted friend's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch(CryptoException e) {
            // this is good. foes shouldn't be able to decrypt friend bytes
        }
        
        try {
            clearbytes2 = foe.decrypt(meCipherBytes);
            assertFalse(
                algorithm + ":foe.decrypt: foe decrypted me's message", 
                Arrays.equals(friendClearBytes, clearbytes2));
        } catch (CryptoException e) {
            // this is good. foes shouldn't be able to decrypt friend bytes
        }
    }
}