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
package net.blackhacker.crypto.utils;

import org.junit.Test;

/**
 *
 * @author ben
 */
public class ValidatorTest {
    
    @Test(expected=NullPointerException.class)
    public void notNull_NullTest() {
        Validator.notNull((String)null, "");
    }

    @Test(expected=RuntimeException.class)
    public void isTrue_FalseTest() {
        Validator.isTrue(false, "");
    }

    public void isTrue_TrueTest() {
        Validator.isTrue(true, "");
    }
    
    @Test(expected=RuntimeException.class)
    public void isA_NegativeTest() {
        Validator.isA(new Object(), String.class, "");
    }

    public void isA_PositiveTest() {
        Validator.isA("", String.class, "");
    }
    
    @Test(expected=RuntimeException.class)
    public void isPositive_ZeroTest() {
        Validator.isPositive(0, "");
    }
    
    @Test(expected=RuntimeException.class)
    public void isPositive_NegativeTest() {
        Validator.isPositive(-1, "");
    }

    public void isPositive_PositiveTest() {
        Validator.isPositive(1, "");
    }
    
    @Test(expected=RuntimeException.class)
    public void isNegative_ZeroTest() {
        Validator.isNegative(0, "");
    }
    
    public void isNegative_NegativeTest() {
        Validator.isNegative(-1, "");
    }

    @Test(expected=RuntimeException.class)
    public void isNegative_PositiveTest() {
        Validator.isNegative(1, "");
    }
    
    public void isZero_ZeroTest() {
        Validator.isZero(0, "");
    }
    
    @Test(expected=RuntimeException.class)
    public void isZero_NegativeTest() {
        Validator.isZero(-1, "");
    }

    @Test(expected=RuntimeException.class)
    public void isZero_PositiveTest() {
        Validator.isZero(1, "");
    }
    
        @Test(expected=RuntimeException.class)
    public void isNotZero_ZeroTest() {
        Validator.isNotZero(0, "");
    }
    
    public void isNotZero_NegativeTest() {
        Validator.isNotZero(-1, "");
    }

    public void isNotZero_PositiveTest() {
        Validator.isNotZero(1, "");
    }
}
