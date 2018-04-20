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
package net.blackhacker.crypto;

/**
 *
 * @author Benjamin King aka Blackhacker<bh@blackhacker.net>
 */
final public class Validator {
    static public <T> T notNull(T t, String parameterName) {
        if (t == null)
            throw new NullPointerException(
                    String.format(Strings.NOT_NULL_MSG_FMT, parameterName));
        return t;
    }
    
    /**
     * 
     * @param test
     * @param message 
     */
    static public void isTrue(boolean test, String message) {
        _test(test, message);
    }
    /**
     * 
     * @param test
     * @param message 
     */
    static public void isFalse(boolean test, String message) {
        _test(!test, message);
    }
    
    /**
     * Throws RuntimeException when object
     * 
     * @param o
     * @param clazz
     * @param parameterName 
     */
    static public void isA(Object o, Class clazz, String parameterName) {
        _test(
            clazz.isInstance(o), 
            Strings.SHOULD_BE_A_MSG_FMT, 
            parameterName, clazz.getName());
    }
    
    /**
     * Throws RuntimeException when num less than zero
     * 
     * @param num
     * @param parameterName 
     */
    static public void isPositive(int num, String parameterName) {
        _test(num > 0, Strings.MUST_BE_POSITIVE_MSG_FMT, parameterName);
    }
    
    /**
     * 
     * @param num
     * @param value
     * @param parameterName 
     */
    static public int lt(int num, int value, String parameterName) {
        _test(num < value, Strings.MUST_BE_LESS_THAN_MSG_FMT, parameterName, value);
        return num;
    }
    
    static public int lte(int num, int value, String parameterName) {
        _test(num <= value, Strings.MUST_BE_LESS_THAN_OR_EQUAL_MSG_FMT, parameterName, value );
        return num;
    }
    
    static public int gt(int num, int value, String parameterName) {
        _test(num > value, Strings.MUST_BE_GREATER_THAN_MSG_FMT, parameterName, value);
        return num;
    }

    static public int gte(int num, int value, String parameterName) {
        _test(num >= value, Strings.MUST_BE_GREATER_THAN_OR_EQUAL_TO_MSG_FMT, parameterName, value);
        return num;
    }
    
    /**
     * 
     * @param x
     * @param msgFormat
     * @param param 
     */
    static private void _test(boolean x, String msgFormat, Object ... param) {
        if (x) return; 
        throw new RuntimeException(String.format(msgFormat, param));
    }
}
