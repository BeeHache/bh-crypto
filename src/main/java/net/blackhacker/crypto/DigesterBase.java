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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public class DigesterBase implements Digester {
    final private MessageDigest messageDigest;
    
    /**
     * Constructor
     * 
     * @param algorithm
     * @throws net.blackhacker.crypto.DigesterException
     */
    protected DigesterBase(String algorithm) throws DigesterException {
    	try {
            messageDigest = MessageDigest.getInstance(algorithm);
    	} catch(NoSuchAlgorithmException e) {
            throw new DigesterException(e);
    	}
    }
    
    /**
     * Constructor
     * 
     * @param messageDigest
     * @see MessageDigest
     */
    protected DigesterBase(MessageDigest messageDigest){
        if (messageDigest==null)
            throw new NullPointerException();
        
        this.messageDigest = messageDigest;
    }

    /**
     *
     * @return algorithm name
     */
    public String getAlgorithm() {
        return messageDigest.getAlgorithm();
    }
    
    /**
     *
     * @param data
     * @return digest of data
     */
    @Override
    public byte[] digest(byte[] data) {
        synchronized(messageDigest) {
            byte[] digest =  messageDigest.digest(data);
            messageDigest.reset();        	
            return digest;
        }
    }
}
