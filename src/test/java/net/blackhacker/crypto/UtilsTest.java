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

public class UtilsTest {
    private Random random = new Random();
    
    @Test
    public void splitConcatTest() {
        byte[] a0 = Utils.concat();
        assertArrayEquals(new byte[0], a0);
        
        a0 = Utils.concat(null);
        assertArrayEquals(new byte[0], a0);
        
        byte[] a1 = new byte[ random.nextInt(100)];
        byte[] a2 = new byte[ random.nextInt(100)];
        byte[] a3 = new byte[ random.nextInt(100)];
        byte[] a4 = null;
        byte[] a5 = new byte[ random.nextInt(100)];
        
        random.nextBytes(a1);
        random.nextBytes(a2);
        random.nextBytes(a3);
        random.nextBytes(a5);
        
        byte[] data = Utils.concat(a1, a2, a3, a4, a5);
        
        assertEquals(a1.length + a2.length + a3.length + a5.length, data.length);
        int dx=0;
        for (byte[] aix : new byte[][]{a1,a2,a3,a4,a5}) {
            if (aix!=null) for (byte b : aix) {
                assertEquals(b, data[dx++]);
            }
        }
        
        byte[] b1 = new byte[a1.length];
        byte[] b2 = new byte[a2.length];
        byte[] b3 = new byte[a3.length];
        byte[] b4 = null;
        byte[] b5 = new byte[a5.length];
        
        Utils.split(data, b1, b2, b3, b4, b5);
        
        assertArrayEquals(a1, b1);
        assertArrayEquals(a2, b2);
        assertArrayEquals(a3, b3);
        assertArrayEquals(a5, b5);
    }
    
    @Test
    public void toIntToBytesTest(){
        int ri = random.nextInt();
        assertEquals(ri, Utils.toInt(Utils.toBytes(ri)));
        
        byte[] rb = new byte[4];
        random.nextBytes(rb);
        assertArrayEquals(rb, Utils.toBytes(Utils.toInt(rb)));
        
    }
    
}
