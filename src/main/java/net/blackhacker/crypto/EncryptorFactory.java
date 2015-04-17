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

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
final public class EncryptorFactory {
    
    /**
     * Factory method for generating PK object using RSA
     * 
     * @return PK object
     * @throws CryptoException
     * @see PK
     */
    static public PK newRSA() throws CryptoException {
        return new PK("RSA", null);
    }
    
    /**
     * Factory method for building PK object from public and private keys using RSA
     * 
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @return PK object
     * @throws CryptoException
     */
    static public PK newRSA(final byte[] publicKeyEncoded, final byte[] privateKeyEncoded) throws CryptoException {
        return new PK("RSA", null, publicKeyEncoded, privateKeyEncoded);
    }


    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : ECB
     * 
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithECB() throws CryptoException {
        return new SK("DES/ECB/PKCS5Padding", "DES", null);
    }

    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : ECB
     * 
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithECB(byte[] key) throws CryptoException {
        try {
            return new SK("DES/ECB/PKCS5Padding", "DES", null, new DESKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @param iv initialization vector
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCBC(byte[] iv) throws CryptoException {
        return new SK("DES/CBC/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCBC(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/CBC/PKCS5Padding","DES",IV64_BIT_CHECK(iv),new DESKeySpec(key)
            );
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCBC() throws CryptoException {
        return newDESWithCBC(RANDOM_64_BITS());
    }

    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCFB(byte[] iv) throws CryptoException {
        return new SK("DES/CFB/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/CFB/PKCS5Padding","DES", IV64_BIT_CHECK(iv), new DESKeySpec(key)
            );
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithCFB() throws CryptoException {
        return newDESWithCFB(RANDOM_64_BITS());
    }    

    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithOFB(byte[] iv) throws CryptoException {
        return new SK("DES/OFB/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/OFB/PKCS5Padding","DES", IV64_BIT_CHECK(iv), new DESKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }
    
    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESWithOFB() throws CryptoException {
        return newDESWithOFB(RANDOM_64_BITS());
    }
    
    
    /**
     * Algorithm : Triple DES
     * Mode : ECB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithECB() throws CryptoException {
        return new SK("DESede/ECB/PKCS5Padding", "DESede", null);
    }

    /**
     * Algorithm : Triple DES
     * Mode : ECB
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithECB(byte[] key) throws CryptoException {
        try {
            return new SK("DESede/ECB/PKCS5Padding", "DESede", null, new DESedeKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Algorithm : Triple DES
     * Mode : CBC
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCBC(byte[] iv) throws CryptoException {
        return new SK("DESede/CBC/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCBC(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DESede/CBC/PKCS5Padding","DESede", IV64_BIT_CHECK(iv), new DESedeKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCBC() throws CryptoException {
        return newDESedeWithCBC(RANDOM_64_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCFB(byte[] iv) throws CryptoException {
        return new SK("DESede/CFB/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv)
        );
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DESede/CFB/PKCS5Padding","DESede", IV64_BIT_CHECK(iv), new DESedeKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithCFB() throws CryptoException {
        return newDESedeWithCFB(RANDOM_64_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithOFB(byte[] iv) throws CryptoException {
        return new SK("DESede/OFB/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
                    "DESede/OFB/PKCS5Padding",
                    "DESede",
                    IV64_BIT_CHECK(iv),
                    new DESedeKeySpec(key)
            );
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newDESedeWithOFB() throws CryptoException {
        return newDESedeWithOFB(RANDOM_64_BITS());
    }
    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithECB(byte[] key) throws CryptoException {
        return new SK(
                "AES/ECB/PKCS5Padding",
                "AES",
                null,
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithECB() throws CryptoException {
        return newAES128WithECB(RANDOM_BITS(128));
    }
    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CBC/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCBC(byte[] iv) throws CryptoException {
        return newAES128WithCBC(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCBC() throws CryptoException {
        return newAES128WithCBC(RANDOM_128_BITS(), RANDOM_128_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCFB(final byte[] iv, final byte[] key) 
            throws CryptoException {
        return new SK(
                "AES/CFB/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCFB(final byte[] iv) throws CryptoException {
        return newAES128WithCFB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCFB() throws CryptoException {
        return newAES128WithCFB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/OFB/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOFB(byte[] iv) throws CryptoException {
        return newAES128WithOFB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOFB() throws CryptoException {
        return newAES128WithOFB(DEFAULT_IV128, RANDOM_128_BITS());
    }
    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCTR(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CTR/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCTR(byte[] iv) throws CryptoException {
        return newAES128WithCTR(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithCTR() throws CryptoException {
        return newAES128WithCTR(DEFAULT_IV128, RANDOM_128_BITS());
    }
    

   /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOCB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/OCB/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOCB(byte[] iv) throws CryptoException {
        return newAES128WithOCB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES128WithOCB() throws CryptoException {
        return newAES128WithOCB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES192WithECB(byte[] key) throws CryptoException {
        return new SK("AES/ECB/PKCS5Padding","AES",null,KEY192_BIT_CHECK(key, "AES"));
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK newAES192WithECB() throws CryptoException {
        return newAES192WithECB(RANDOM_192_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK newARANDOM_BITS92WithCBC(byte[] iv) throws CryptoException {
        return newAES192WithCBC(iv, RANDOM_192_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK newAES192WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CBC/PKCS5Padding",
                "AES",
                IV192_BIT_CHECK(iv),
                KEY192_BIT_CHECK(key, "AES")
        );
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstancRANDOM_BITSS192WithCBC() throws CryptoException {
        return newAES192WithCBC(DEFAULT_IV128, RANDOM_192_BITS());
    }
    
    
    /**
     * Generates byte array containing 64 bits
     * @return byte array of random 8 bytes (64 bits) long
     */
    static private byte[] RANDOM_64_BITS() {
        return RANDOM_BITS(64);
    }

    /**
     * Generates byte array containing 128 bits
     * @return byte array of random 16 bytes (128 bits) long
     */
    static private byte[] RANDOM_128_BITS() {
        return RANDOM_BITS(128);
    }
    
    /**
     * Generates byte array containing 192 bits
     * @return byte array of random 34 bytes (192 bits) long
     */
    static private byte[] RANDOM_192_BITS() {
        return RANDOM_BITS(192);
    }
    
    /**
     * Generates byte array containing 64 bits
     * 
     * @param size size of array in bits, should be multiple of 8
     * @return A random array of bytes
     */
    static private byte[] RANDOM_BITS(int size) {
        int sizeInBytes =(int) Math.ceil(((double)size) / 8.0);
        byte[] key = new byte[sizeInBytes];
        SECURE_RANDOM.nextBytes(key);
        return key;
    }
    
    /**
     * Checks the key is the given size in bits and builds SecreteKeySpec object
     * from key and algorithm
     * 
     * @param key encoded bytes of secret key. If null then a random key is generated.
     * @param algorithm Algorithm name
     * @param size size of key in bits. It should be (64, 128, 192 or 256) if key
     * is null
     * @return SecretKeySpec object
     * @throws CryptoException when key is the incorrect size for the given size
     * @see javax.crypto.spec.SecretKeySpec
     */
    static private SecretKeySpec KEY_BIT_CHECK(final byte[] key, final String algorithm, final int size) 
            throws CryptoException {
        
        if (key==null){
            switch(size){
                case 64:
                case 128:
                case 192:
                case 256:
                    return new SecretKeySpec(RANDOM_BITS(size), algorithm);

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }            
        } else if (key.length !=  (size / 8)){
            throw new CryptoException("key must " + size + " bits");
        }
        
        return new SecretKeySpec(key, algorithm);
    }
    /**
     * Verifies the size of IV, and wraps with IvParameterSpec
     * 
     * @param iv byte array of IV. if NULL then DEFAULT_IV64 or DEFAULT_IV128 is
     * used
     * @param size expected size of IVin bits. Should be 64 or 128.
     * @return IvParameterSpec object from iv
     * @throws CryptoException 
     * @see javax.crypto.spec.IvParameterSpec
     */
    static private IvParameterSpec IV_BIT_CHECK(final byte[] iv, int size)
            throws CryptoException {
        
        if (iv == null) {
            switch(size) {
                case 64:
                    return new IvParameterSpec(DEFAULT_IV64);

                case 128:
                    return new IvParameterSpec(DEFAULT_IV128);

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }
        } else if (iv.length !=  (size / 8)) {
            throw new CryptoException("IV must " + size + " bits");
        }
            return new IvParameterSpec(iv);
    }
    
    /**
     * Verifies that the IV is 64 bits. Same as IV_BIT_CHECK(iv,64)
     * 
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static private IvParameterSpec IV64_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 64);
    }
    
    /**
     * Verifies that the IV is 128 bits. Same as IV_BIT_CHECK(iv,128)
     * 
     * @param iv Initialization Vector
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static private IvParameterSpec IV128_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 128);
    }
    /**
     * Verifies that the IV is 192 bits. Same as IV_BIT_CHECK(iv,192)
     * 
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */
    static private IvParameterSpec IV192_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 192);
    }
    
    /**
     * Verifies that the IV is 128 bits. Same as IV_BIT_CHECK(iv,256)
     * 
     * @param iv
     * @return IvParameterSpec object from iv
     * @throws CryptoException
     * @see javax.crypto.spec.IvParameterSpec
     */    
    static private IvParameterSpec IV256_BIT_CHECK(byte[] iv) throws CryptoException {
        return IV_BIT_CHECK(iv, 256);
    }

    /**
     * Checks the key is 128 bits and builds SecreteKeySpec object from key and algorithm
     * 
     * @param key Key object encoded in bytes
     * @param algorithm 
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see javax.crypto.spec.SecretKeySpec
     */
    static private SecretKeySpec KEY128_BIT_CHECK(byte[] key, String algorithm) throws CryptoException {
        return KEY_BIT_CHECK(key, algorithm, 128);
    }
    
    /**
     * Checks the key is 192 bits and builds SecreteKeySpec object from key and algorithm
     * 
     * @param key Key object encoded in bytes
     * @param algorithm 
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see javax.crypto.spec.SecretKeySpec
     */
    static private SecretKeySpec KEY192_BIT_CHECK(byte[] key, String algorithm) throws CryptoException {
        return KEY_BIT_CHECK(key, algorithm, 192);
    }

    /**
     * Verifies the size of the key is 256
     * 
     * @param key encoded SecreteKey
     * @param algorithm
     * @return SecretKeySpec object from key and algorithm
     * @throws CryptoException
     * @see SecretKeySpec
     */
    static private SecretKeySpec KEY256_BIT_CHECK(byte[] key, String algorithm) throws CryptoException {
        return KEY_BIT_CHECK(key,algorithm, 256);
    }

    
    /**
     * default 64 bit Intialization Vector
     */
    static final private byte[] DEFAULT_IV64 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb
    };

    /**
     * default 128 bit Intialization Vector
     */
    static final private byte[] DEFAULT_IV128 = {
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
        (byte)0xc9, (byte)0x95, (byte)0x9b, (byte)0x10,
        (byte)0xf4, (byte)0xee, (byte)0x15, (byte)0xeb,
    };
    
    /**
     * SecureRandom
     */
    final static private SecureRandom SECURE_RANDOM = new SecureRandom();    
}