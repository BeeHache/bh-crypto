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
package net.blackhacker.crypto.algorithm;

import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collection;
import net.blackhacker.crypto.CryptoException;
import org.junit.Assert;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author ben
 */
@RunWith(Parameterized.class)
public class SymetricAlgorithmTest {
    
    final private SymetricAlgorithm algorithm;
    
    public SymetricAlgorithmTest(SymetricAlgorithm algorithm){
        this.algorithm = algorithm;
    }
    
    @Parameterized.Parameters
    public static Collection<SymetricAlgorithm[]> data() throws CryptoException {
        Collection<SymetricAlgorithm[]> l = new ArrayList<>();
        for (SymetricAlgorithm sa : SymetricAlgorithm.values()) {
            l.add(new SymetricAlgorithm[]{sa});
        }
        return l;
    }
    
    @Test
    public void gettersTest() {
        assertTrue("block size", algorithm.getBlockSize() > 0);
        assertNotNull("PBE name", algorithm.getPBEName());
        assertNotNull("KeySpec Class", algorithm.getKeySpecClass());
        assertNotNull("AlgorithmParameterSpec Class", 
                algorithm.getAlgorParamSpecClass());
    }
    
    @Test
    public void makeKeySpecTest() throws CryptoException {
        int x = 100;
        byte[] b= new byte[algorithm.getBlockSize()];
        assertNotNull(algorithm.makeKeySpec(b));
        
        try {
            algorithm.makeKeySpec();
            fail("empty params");
        } catch(RuntimeException e){
        }

        try {
            algorithm.makeKeySpec(new Object());
            fail("arbitrary params");
        } catch(CryptoException e){
        }
    }

    @Test
    public void makeParameterTest() throws CryptoException {
        int x = 100;
        byte[] b= new byte[algorithm.getBlockSize()];
        assertNotNull(algorithm.makeParameterSpec(b));
        
        try {
            algorithm.makeParameterSpec();
            fail("empty params");
        } catch(RuntimeException e){
        }
        
        try {
            algorithm.makeParameterSpec(new Object());
            fail("arbitrary params");
        } catch(CryptoException e){
        }
    }    
}
