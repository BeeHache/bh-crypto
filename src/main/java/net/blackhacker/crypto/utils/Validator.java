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

import java.util.regex.Pattern;

/**
 *
 * @author Benjamin King aka Blackhacker&lt;bh@blackhacker.net&gt;
 */
final public class Validator {
    
    /**
     * Throws a NullPointerException if t is null
     * 
     * @param t Object to be null checked
     * @param parameterName parameter name of passed in object
     * @return object unchanged if not null
     */
    static public <T> T notNull(T t, String parameterName) {
        if (t == null)
            throw new NullPointerException(
                    String.format(NOT_NULL_MSG_FMT, parameterName));
        return t;
    }
    
    /**
     * throws runtime exception unless given test value is true
     * 
     * @param test
     * @param message 
     */
    static public void isTrue(boolean test, String message) {
        _test(test, message);
    }
    /**
     * throws runtime exception unless given test value is false
     * 
     * @param test
     * @param message 
     */
    static public void isFalse(boolean test, String message) {
        isTrue(!test,message);
    }
    
    /**
     * Throws RuntimeException when object
     * 
     * @param <T>
     * @param t
     * @param clazz
     * @param parameterName 
     * @return  
     */
    static public <T> T isA(T t, Class clazz, String parameterName) {
        _test(
            clazz.isInstance(t), 
            SHOULD_BE_A_MSG_FMT, 
            parameterName, clazz.getName());
        return t;
    }
    
    /**
     * Throws RuntimeException when num less than zero
     * 
     * @param num
     * @param parameterName 
     * @return  
     */
    static public int isPositive(int num, String parameterName) {
        _test(num > 0, MUST_BE_POSITIVE_MSG_FMT, parameterName);
        return num;
    }

    /**
     * 
     * @param num
     * @param parameterName
     * @return 
     */
    static public int isNegative(int num, String parameterName) {
        _test(num < 0, MUST_BE_POSITIVE_MSG_FMT, parameterName);
        return num;
    }

    /**
     * 
     * @param num
     * @param parameterName
     * @return 
     */
    static public int isZero(int num, String parameterName) {
        _test(num == 0, MUST_BE_POSITIVE_MSG_FMT, parameterName);
        return num;
    }
    
    /**
     * 
     * @param num
     * @param parameterName
     * @return 
     */
    static public int isNotZero(int num, String parameterName) {
        _test(num != 0, MUST_BE_POSITIVE_MSG_FMT, parameterName);
        return num;
    }    
    
    /**
     * 
     * @param num
     * @param value
     * @param parameterName 
     * @return  
     */
    static public int lt(int num, int value, String parameterName) {
        _test(num < value, MUST_BE_LESS_THAN_MSG_FMT, parameterName, value);
        return num;
    }
    
    /**
     *
     * @param num
     * @param value
     * @param parameterName
     * @return
     */
    static public int lte(int num, int value, String parameterName) {
        _test(num <= value, MUST_BE_LESS_THAN_OR_EQUAL_MSG_FMT, parameterName, value );
        return num;
    }
    
    /**
     * 
     * @param num
     * @param value
     * @param parameterName
     * @return 
     */
    static public int gt(int num, int value, String parameterName) {
        _test(num > value, MUST_BE_GREATER_THAN_MSG_FMT, parameterName, value);
        return num;
    }

    /**
     * 
     * @param num
     * @param value
     * @param parameterName
     * @return 
     */
    static public int gte(int num, int value, String parameterName) {
        _test(num >= value, MUST_BE_GREATER_THAN_OR_EQUAL_TO_MSG_FMT, parameterName, value);
        return num;
    }
    
    /**
     * 
     * @param num
     * @param value
     * @param parameterName
     * @return 
     */
    static public int eq(int num, int value, String parameterName) {
        _test(num==value, "");
        return num;
    }
    
    /**
     * 
     * @param num
     * @param value
     * @param parameterName
     * @return 
     */
    static public int ne(int num, int value, String parameterName) {
        _test(num!=value,"");
        return num;
    }
    
    /**
     * 
     * @param string
     * @param pattern
     * @return 
     */
    static public String matches(String string, Pattern pattern) {
        _test(pattern.matcher(string).matches(), "");
        return string;
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
    
    final static public String NOT_NULL_MSG_FMT 
            = "%s can't be null";
    final static public String MUST_BE_POSITIVE_MSG_FMT
            = "%s must be positive";
    final static public String MUST_BE_LESS_THAN_MSG_FMT
            = "%s must be less than %s";
    final static public String MUST_BE_LESS_THAN_OR_EQUAL_MSG_FMT
            = "%s must be less than or equal to %s";
    final static public String MUST_BE_GREATER_THAN_MSG_FMT
            = "%s must be greater than %s";
    final static public String MUST_BE_GREATER_THAN_OR_EQUAL_TO_MSG_FMT
            = "%s must be greater than or equal to %s";
    final static public String SHOULD_BE_A_MSG_FMT 
            = "%s should be a %s";
}
