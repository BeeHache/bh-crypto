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
public class SymetricAlgorithmTest {
    
    final private SymmetricAlgorithm algorithm;
    
    public SymetricAlgorithmTest(SymmetricAlgorithm algorithm){
        this.algorithm = algorithm;
    }
    
    @Parameterized.Parameters
    public static Collection<SymmetricAlgorithm[]> data() throws CryptoException {
        Collection<SymmetricAlgorithm[]> l = new ArrayList<>();
        for (SymmetricAlgorithm sa : SymmetricAlgorithm.values()) {
            l.add(new SymmetricAlgorithm[]{sa});
        }
        return l;
    }
    
    @Test
    public void gettersTest() {
        assertTrue("block size", algorithm.getBlockSize() > 0);
        assertNotNull("PBE name", algorithm.getTransformationName());
        assertNotNull("KeySpec Class", algorithm.getKeySpecClass());
        assertNotNull("AlgorithmParameterSpec Class", 
                algorithm.getAlgorParamSpecClass());
    }
    
    @Test
    public void makeKeySpecNotNullTest() throws CryptoException {
        assertNotNull(algorithm.makeKeySpec(new byte[algorithm.getBlockSize()]));
    }
    
    @Test(expected=RuntimeException.class)
    public void makeKeySpecEmptyTest() throws CryptoException {
        algorithm.makeKeySpec();
        fail("empty params");
    }
    
    @Test(expected=CryptoException.class)
    public void makeKeySpecArbitraryTest() throws CryptoException {
        algorithm.makeKeySpec(new Object());
        fail("arbitrary params");
    }
    
    @Test
    public void makeParameterNotNullTest() throws CryptoException {
        assertNotNull(algorithm.makeParameterSpec(new byte[algorithm.getBlockSize()]));
    }

    @Test(expected=RuntimeException.class)
    public void makeParameterEmptyTest() throws CryptoException {        
        algorithm.makeParameterSpec();
        fail("empty params");
    }    

    @Test(expected=CryptoException.class)
    public void makeParameterArbitraryTest() throws CryptoException {
        algorithm.makeParameterSpec(new Object());
        fail("arbitrary params");
    }
}
