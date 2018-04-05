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
 * Messages and message formats
 * 
 * @author Benjamin King aka Blackhacker<bh@blackhacker.net>
 */
final public class Strings {
    final static public String NOT_NULL_MSG_FMT 
            = "%s can't be null";
    final static public String COULDNT_CREATE_CIPHER_MSG_FMT 
            = "Couldn't generate cipher for %s : %s";
    final static public String COULDNT_CREATE_KEY_SPEC_MSG_FMT 
            = "Couldn't create key spec :%s : %s";
    final static public String COULDNT_CREATE_PARAM_SPEC_MSG_FMT 
            = "Couldn't create parameter spec :%s : %s";
    final static public String COULDNT_CREATE_KEY_FACT_MSG_FMT 
            = "Couldn't create key factory: %s : %s";
    final static public String COULDNT_ENCRYPT_MSG_FMT 
            = "Could not encrypt data: %s : %s";
    final static public String COULDNT_DECRYPT_MSG_FMT 
            = "Could not decrypt data: %s : %s";
    final static public String NON_PBE_MSG 
            = "This constructor requires a non-PBE Transformation.";
    final static public String PBE_MSG 
            = "This constructor requires a PBE Transformation.";
    final static public String SHOULD_BE_A 
            = "%s should be a %s";
    final static public String NOT_SYMETRIC_MSG 
            = "This Transformation is not for a Symetric Algorithm";
    final static public String NOT_ASYMETRIC_MSG 
            = "This Transformation is not for a Asymetric Algorithm";
}