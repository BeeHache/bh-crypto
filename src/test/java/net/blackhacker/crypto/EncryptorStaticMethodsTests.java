/*
 * The MIT License
 *
 * Copyright 2015 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.util.Arrays;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 *
 * @author ben
 */
public class EncryptorStaticMethodsTests {
    
    @Test
    public void size0() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(0);
        assertEquals(RANDOM_BITS.length, 0);
    }

    @Test
    public void size1() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(1);
        assertEquals(RANDOM_BITS.length, 1);
    }

    @Test
    public void size7() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(7);
        assertEquals(RANDOM_BITS.length, 1);
    }
    
    @Test
    public void size8() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(8);
        assertEquals(RANDOM_BITS.length, 1);
    }
    
    @Test
    public void size9() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(9);
        assertEquals(RANDOM_BITS.length, 2);
    }

    @Test
    public void size15() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(15);
        assertEquals(RANDOM_BITS.length, 2);
    }

    @Test
    public void size16() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(16);
        assertEquals(RANDOM_BITS.length, 2);
    }

    @Test
    public void size17() {
        byte[] RANDOM_BITS = Encryptor.RANDOM_BITS(17);
        assertEquals(RANDOM_BITS.length, 3);
    }
    
    @Test
    public void random() {
        byte[] a1 = Encryptor.RANDOM_BITS(16);
        byte[] a2 = Encryptor.RANDOM_BITS(16);
        boolean areEqual = Arrays.areEqual(a2, a1);
        assertFalse("Encryptor.RANDOM_BITS not random", areEqual);
    }
    
    @Test
    public void IVsize0() {
        try {
            IvParameterSpec IV_BIT_CHECK = Encryptor.IV_BIT_CHECK(null, 0);
            fail("");
        } catch (CryptoException ex) {
        }
    }
    
}
