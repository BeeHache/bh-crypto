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
package net.blackhacker.crypto.utils;

import java.util.Random;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author ben
 */

public class UtilsTest {
    private final Random random = new Random();

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
    
    @Test
    public void concatDefaultTest() {
        assertArrayEquals(new byte[0], Utils.concat());
    }
    
    @Test
    public void concatNullTest() {
        assertArrayEquals(new byte[0], Utils.concat((byte[]) null));
    }
    
    @Test
    public void splitTest() {
        byte[] a1 = new byte[ random.nextInt(20)];
        byte[] a2 = new byte[ random.nextInt(20)];
        byte[] a3 = new byte[ random.nextInt(20)];
        byte[] a4 = null;
        byte[] a5 = new byte[ random.nextInt(20)];
        
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
    }
    
    @Test
    public void concatTest() {
        byte[] a1 = new byte[ random.nextInt(20)];
        byte[] a2 = new byte[ random.nextInt(20)];
        byte[] a3 = new byte[ random.nextInt(20)];
        byte[] a4 = null;
        byte[] a5 = new byte[ random.nextInt(20)];
        
        random.nextBytes(a1);
        random.nextBytes(a2);
        random.nextBytes(a3);
        random.nextBytes(a5);
        
        byte[] data = Utils.concat(a1, a2, a3, a4, a5);
        
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
        
        byte[] rb = new byte[Integer.BYTES];
        random.nextBytes(rb);
        assertArrayEquals(rb, Utils.toBytes(Utils.toInt(rb)));
        
    }

    /**
     * Test of getClasses method, of class Utils.
     */
    @Test
    public void getClassesTest() {
        Object[] objs = {1,(long)1 ,(float)1.0, (double)1.0, "ONE"};
        Class[] expResult = {int.class, long.class, float.class, double.class,
            String.class};
        Class[] result = Utils.getClasses(objs);
        assertArrayEquals(expResult, result);
    }
    
}
