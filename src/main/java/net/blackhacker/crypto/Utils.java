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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author ben
 */
public class Utils {

    /**
     * Returns true if Java Encryption Extension (JCE) is installed
     * 
     * @return true if JCE is installed
     */
    static public boolean jce() {
        return false;
        /***
        try {
            int makl = Cipher.getMaxAllowedKeyLength("AES");
            return  makl == Integer.MAX_VALUE;
        } catch (NoSuchAlgorithmException ex) {
            return false;
        }
        ***/
    }

    /**
     * Returns an array of Class objects for the parameters given
     * 
     * @param objs
     * @return array of Class objects
     * @see Class
     */
    static final public Class<?>[] getClasses(Object... objs) {
        List<Class<?>> classes = new ArrayList<>();
        for(Object obj : objs) {
            Class<?> aClass = obj.getClass();
            if (aClass.equals(Integer.class)) {
                aClass = int.class;
            } else if (aClass.equals(Long.class)){
                aClass = long.class;
            } else if (aClass.equals(Float.class)){
                aClass = float.class;
            } else if (aClass.equals(Double.class)){
                aClass = double.class;
            }
            classes.add(aClass);
        }
        
        return classes.toArray(new Class<?>[0]);
    }


    /**
     *  Concatenates multiple byte arrays into a single target
     * 
     * @param arrays  a list of byte arrays to be concatenated
     * @return  the concatenated byte target
     */
    static public byte[] concat(byte[]... arrays){
        int bufferSize = 0;
        if (arrays!=null) for(byte[] array : arrays) {
            bufferSize+= array==null ? 0 : array.length;
        }
        
        byte[] buffer = new byte[bufferSize];
        if (arrays!=null) {
            int i = 0;
            for (byte[]array : arrays){
                if (array!=null)
                    for (int a=0 ; a < array.length; a++)
                        buffer[i++] = array[a];
            }
        }
        
        return buffer;
    }
    
    /**
     * Reverse of the concat method, it copies the contents of one byte array
     * to multiple arrays
     * 
     * @param source source byte array
     * @param targets target byte arrays
     */
    static public void split(byte[] source, byte[]... targets) {
        int sx = 0;
        if (source != null) try {
            for (byte[] target : targets) {
                if (target != null)
                    for(int tx=0; tx < target.length; tx++) {
                        target[tx] = source[sx++];
                    }
            }
        }catch(IndexOutOfBoundsException e) {
        }
    }
    
    /**
     * Converts integer to a byte array
     * 
     * @param i integer to be converted
     * @return byte[] representation of given integer
     */
    static public byte[] toBytes(int i){
        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES);
        bb.putInt(i);
        return bb.array();
    }
    
    /**
     *  Reads bytes from an array and converts them to an integer
     * 
     * @param b byte array
     * @return integer
     */
    static public int toInt(byte[] b){
        ByteBuffer bb = ByteBuffer.wrap(b);
        return bb.getInt();
    }
    
    /**
     * Calculates the number of bytes needed to contain a given number of bits.
     * 
     * @param bits
     * @return  byte count
     */
    static public int bitsToBytes(int bits) {
        return (int) Math.ceil((double)bits / 8.0);
    }
}
