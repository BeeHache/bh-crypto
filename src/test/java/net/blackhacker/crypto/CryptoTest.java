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

import java.util.Random;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 * @author ben
 */

public class CryptoTest {
    
    @Test
    public void test() {
        Random r = new Random();
        
        byte[] a1 = new byte[ r.nextInt(100)];
        byte[] a2 = new byte[ r.nextInt(100)];
        byte[] a3 = new byte[ r.nextInt(100)];
        
        r.nextBytes(a1);
        r.nextBytes(a2);
        r.nextBytes(a3);
        
        byte[] data = Crypto.concat(a1, a2, a3);
        
        assertEquals(a1.length + a2.length + a3.length, data.length);
        
        byte[] b1 = new byte[a1.length];
        byte[] b2 = new byte[a2.length];
        byte[] b3 = new byte[a3.length];
        
        Crypto.split(data, b1, b2, b3);
        
        assertArrayEquals(a1, b1);
        assertArrayEquals(a2, b2);
        assertArrayEquals(a3, b3);
        
    }
    
}
