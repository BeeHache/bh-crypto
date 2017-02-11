/*
 * The MIT License
 *
 * Copyright 2017 ben.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class
 * 
 * @author ben
 */
final public class Utils {    
    /**
     * Concatenates a list of byte arrays into a single byte array
     * 
     * @param arrays
     * @return single array containing contents of all arrays
     */
    
    static public byte[] joinArrays(final byte[] ...arrays) {
        Validator.notNull(arrays, "arrays");
        int sum=Arrays.asList(arrays).stream().mapToInt( n -> n!=null ? n.length : 0).sum();
        
        byte[] retval = new byte [ sum ];
        int r = 0;
        for (byte[] array : arrays) {
            if (array!=null) {
                for (byte b : array) {
                    retval[r++] = b;
                }
            }
        }
        return retval;
    }
    
    static public byte[][] splitBytes(final byte[]data, final int[] lengths) {
        Validator.notNull(data, "data");
        Validator.notNull(lengths, "lengths");
        int d=0;
        List<byte[]> arrays = new ArrayList<>();
        for (int l=0; l < lengths.length; l++) {
            byte[]array = new byte[lengths[l]];
            for(int a=0; a < array.length; a++){
                array[a] = data[d++];
            }
            arrays.add(array);
        }
        
        return arrays.toArray(new byte[0][]);
    }
}
