/*
 * The MIT License
 *
 * Copyright 2017 Benjamin King aka Blackhacker<bh@blackhacker.net>.
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

import java.util.Random;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 * @author Benjamin King aka Blackhacker<bh@blackhacker.net>
 */
public class UtilsTest {
    
    @Test
    public void joinArrays_null_items_Test() {
        byte[] a = null;
        byte[] b = null;
        byte[] c = Utils.joinArrays(a, b);
        Assert.assertNotNull(c);
    }
    
    @Test
    public void joinArraysTest() {
        Random r = new Random();
        byte[] a1 = new byte[r.nextInt(100)];
        byte[] a2 = new byte[r.nextInt(100)];
        byte[] a3 = new byte[r.nextInt(100)];
        
        int s1 = 0, s2 = 0, s3 = 0, sx = 0;
        
        for (int i = 0; i < a1.length; i++) {
            a1[i] = (byte)i;
            s1 += i;
        }
        
        for (int i = 0; i < a2.length; i++) {
            a2[i] = (byte)i;
            s2 += i;
        }

        for (int i = 0; i < a3.length; i++) {
            a3[i] = (byte)i;
            s3 += i;
        }
        
        byte[] ax = Utils.joinArrays(a1, a2, a3);
        for (int i = 0; i < ax.length; i++){
            sx += (int)ax[i];
        }
        
        assertEquals(s1 + s2 + s3, sx);
        
        byte[][] split = Utils.splitBytes(ax, new int[]{a1.length, a2.length, a3.length});
        assertEquals("", 3, split.length);
        assertArrayEquals("", a1, split[0]);
        assertArrayEquals("", a2, split[1]);
        assertArrayEquals("", a3, split[2]);
    }
    
    
}
