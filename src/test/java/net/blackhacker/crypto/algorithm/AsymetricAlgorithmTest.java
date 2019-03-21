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
package net.blackhacker.crypto.algorithm;

import java.util.ArrayList;
import java.util.Collection;
import net.blackhacker.crypto.CryptoException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 *
 * @author ben
 */
@RunWith(Parameterized.class)
public class AsymetricAlgorithmTest {
    
    final private AsymmetricAlgorithm algorithm;
    
    public AsymetricAlgorithmTest(AsymmetricAlgorithm algorithm){
        this.algorithm = algorithm;
    }
    
    @Parameterized.Parameters
    public static Collection<AsymmetricAlgorithm[]> data() throws CryptoException {
        Collection<AsymmetricAlgorithm[]> l = new ArrayList<>();
        for (AsymmetricAlgorithm sa : AsymmetricAlgorithm.values()) {
            l.add(new AsymmetricAlgorithm[]{sa});
        }
        return l;
    }
    
    @Test
    public void gettersTest() {
        assertTrue("block size", algorithm.getBlockSize() > 0);
    }
    
    @Test
    public void makePublicKeySpecNotNullTest() throws CryptoException {
        assertNotNull(algorithm.makePublicKeySpec(new byte[algorithm.getBlockSize()]));
    }

    @Test(expected=RuntimeException.class)
    public void makePublicKeySpecEmptyTest() throws CryptoException {
        algorithm.makePublicKeySpec();
        fail("empty params");
    }
    
    @Test(expected=CryptoException.class)
    public void makePublicKeySpecArbitraryTest() throws CryptoException {        
            algorithm.makePublicKeySpec(new Object());
            fail("arbitrary params");
    }
    
    @Test
    public void makePrivateKeySpecNotNullTest() throws CryptoException {
        assertNotNull(algorithm.makePrivateKeySpec(new byte[algorithm.getBlockSize()]));
    }
    
    @Test(expected=RuntimeException.class)
    public void makePrivateKeySpecEmptyTest() throws CryptoException { 
        algorithm.makePrivateKeySpec();
        fail("empty params");
    }

    @Test(expected=CryptoException.class)
    public void makePrivateKeySpecArbitraryTest() throws CryptoException { 
        algorithm.makePrivateKeySpec(new Object());
        fail("arbitrary params");
    }
}
