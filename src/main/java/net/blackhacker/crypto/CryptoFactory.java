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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.blackhacker.crypto.Crypto.Algorithm;
import net.blackhacker.crypto.Crypto.Mode;
import net.blackhacker.crypto.Crypto.Padding;

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
final public class CryptoFactory {
    
    static public int RSA_MAX_BYTES = 245;
    
    final static AlgorithmParameterSpec RSA_ALGOR_PARAM_SPEC = 
        new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
    
    /**
     * Factory method for generating PK object using RSA
     * 
     * @return PK object
     * @throws CryptoException
     * @see PK
     */
    static public PK newEncryptorRSAWithECB() throws CryptoException {
        return new PK(
                new Transformation(Algorithm.RSA, Mode.ECB, Padding.PKCS1Padding),
                null, RSA_ALGOR_PARAM_SPEC);
    }
    
    /**
     * Factory method for building PK object from public and private keys using 
     * RSA
     * 
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @return PK object
     * @throws CryptoException
     * @see PK
     */
    static public PK newEncryptorRSAWithECB(
            final byte[] publicKeyEncoded, final byte[] privateKeyEncoded) 
            throws CryptoException {
        return new PK(
                new Transformation(Algorithm.RSA, Mode.ECB, Padding.PKCS1Padding)
                , null,publicKeyEncoded,privateKeyEncoded);
    }

    /**
     *
     * @param publicKeyEncoded
     * @return
     * @throws CryptoException
     */
    static public PK newEncryptorRSAWithECB(final byte[] publicKeyEncoded) 
            throws CryptoException {
        return new PK(
                new Transformation(Algorithm.RSA, Mode.ECB, Padding.PKCS1Padding)
                , null,publicKeyEncoded);
    }  

    /**
     * Factory method for generating SK object using DES algorithm in ECB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithECB() throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DES, Mode.ECB, Padding.PKCS1Padding),
                null);
    }

    /**
     * Factory method for building SK object from encoded key using DES 
     * algorithm in ECB mode
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithECB(byte[] key) throws CryptoException {
        return new SK(new Transformation(Algorithm.DES, Mode.ECB), null, key);
    }    
    
    /**
     * Factory method for generating a new SK object using DES algorithm in CBC 
     * mode with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCBC(byte[] iv) throws CryptoException {
        return new SK(new Transformation(Algorithm.DES, Mode.CBC), IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object from the encoded key using DES
     * algorithm in CBC mode with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(new Transformation(Algorithm.DES, Mode.CBC), IV64_BIT_CHECK(iv), key);
    }    
    
    /**
     * Factory method for generating an SK object using DES algorithm in CBC 
     * mode with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCBC() throws CryptoException {
        return newEncryptorDESWithCBC(DEFAULT_IV64);
    }

    /**
     * Factory method for generating an SK object using DES algorithm in CFB 
     * mode with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DES, Mode.CFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object from the encoded key using DES
     * algorithm in CFB mode with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DES, Mode.CFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv), key);
    }    
    
    /**
     * Factory method for generating an SK object using DES algorithm in CFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB() throws CryptoException {
        return newEncryptorDESWithOFB(DEFAULT_IV64);
    }    

    /**
     * Factory method for building an SK object using DES algorithm in OFB mode
     * with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DES, Mode.OFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object from the encoded key using DES
     * algorithm in OFB mode with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DES, Mode.OFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv), key);
    }
    
    /**
     * Factory method for building an SK object using DES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB() throws CryptoException {
        return newEncryptorDESWithOFB(DEFAULT_IV64);
    }
    
    
    /**
     * Factory method for building an SK object using Triple DES algorithm in ECB mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithECB() throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DESede, Mode.ECB, Padding.PKCS5Padding),
                null);
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in ECB mode
     *
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithECB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.DESede, Mode.ECB, Padding.PKCS5Padding),
            null, key);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in CBC mode with the given IV
     *
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCBC(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DESede, Mode.CBC, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in CBS mode with the given IV
     *
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.DESede, Mode.CBC, Padding.PKCS5Padding),
            IV64_BIT_CHECK(iv), key);
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCBC() throws CryptoException {
        return newEncryptorDESedeWithCBC(DEFAULT_IV64);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in CFB mode with the given IV
     *
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCFB(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DESede, Mode.CFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv)
        );
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in CFB mode with the given IV
     *
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.DESede, Mode.CFB, Padding.PKCS5Padding),
            IV64_BIT_CHECK(iv), key);
    }    
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in CFB mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCFB() throws CryptoException {
        return newEncryptorDESedeWithCFB(DEFAULT_IV64);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in OFB mode with the given IV
     *
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithOFB(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DESede, Mode.OFB, Padding.PKCS5Padding),
                IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in OFB mode with the given IV
     *
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.DESede, Mode.OFB, Padding.PKCS5Padding),
            IV64_BIT_CHECK(iv), key);
    }    
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in OFB mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithOFB() throws CryptoException {
        return newEncryptorDESedeWithOFB(DEFAULT_IV64);
    }

    /**
     * Factory method for building an SK object using AES algorithm
     * from encoded key in CFB mode
     *
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithECB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.ECB, Padding.PKCS5Padding), null,key);
    }

    /**
     * Factory method for building an SK object using AES algorithm 
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithECB() throws CryptoException {
        return newEncryptorAES128WithECB(RANDOM_BITS(128));
    }    
    
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC(byte[] iv) throws CryptoException {
        return new SK(
                new Transformation(Algorithm.DESede, Mode.CBC, Padding.PKCS5Padding),
                IV128_BIT_CHECK(iv));
    }

    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC() throws CryptoException {
        return newEncryptorAES128WithCBC(DEFAULT_IV128);
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.CBC, Padding.PKCS5Padding),
            IV128_BIT_CHECK(iv), key);
    }

    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCFB(final byte[] iv, final byte[] key) 
            throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.CFB, Padding.PKCS5Padding),
            IV128_BIT_CHECK(iv), key
        );
    }

    /**
     * Factory method for building an SK object using AES algorithm in CFB mode
     * with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCFB(final byte[] iv) throws CryptoException {
        return newEncryptorAES128WithCFB(iv, RANDOM_128_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCFB() throws CryptoException {
        return newEncryptorAES128WithCFB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.OFB, Padding.PKCS5Padding),
            IV128_BIT_CHECK(iv), key
        );
    }

    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB(byte[] iv) throws CryptoException {
        return newEncryptorAES128WithOFB(iv, RANDOM_128_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB() throws CryptoException {
        return newEncryptorAES128WithOFB(DEFAULT_IV128, RANDOM_128_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CTR mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCTR(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.CTR, Padding.PKCS5Padding),
            IV128_BIT_CHECK(iv), key
        );
    }

    /**
     * Factory method for building an SK object using AES algorithm in CTR mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCTR(byte[] iv) throws CryptoException {
        return newEncryptorAES128WithCTR(iv, RANDOM_128_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CTR mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCTR() throws CryptoException {
        return newEncryptorAES128WithCTR(DEFAULT_IV128, RANDOM_128_BITS());
    }
    

    /**
     * Factory method for building an SK object using AES algorithm in OCB mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOCB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.OCB, Padding.PKCS5Padding),
            IV128_BIT_CHECK(iv), key
        );
    }

    /**
     * Factory method for building an SK object using AES algorithm in OCB mode
     * from encoded key
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOCB(byte[] iv) throws CryptoException {
        return newEncryptorAES128WithOCB(iv, RANDOM_128_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in OCB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOCB() throws CryptoException {
        return newEncryptorAES128WithOCB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     * Factory method for building an SK object using AES algorithm in ECB mode
     * from encoded key
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithECB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.ECB, Padding.PKCS5Padding),
            null, key);
    }    
    
    /**
     * Factory method for building an SK object using AES algorithm in ECB mode
     * from encoded key with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithECB() throws CryptoException {
        return newEncryptorAES192WithECB(RANDOM_192_BITS());
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *  with the given IV
     * 
     * @param iv
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithCBC(byte[] iv) throws CryptoException {
        return newEncryptorAES192WithCBC(iv, RANDOM_192_BITS());
    }

    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param iv
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
            new Transformation(Algorithm.AES, Mode.CBC, Padding.PKCS5Padding),
            IV192_BIT_CHECK(iv), key
        );
    }    
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithCBC() throws CryptoException {
        return newEncryptorAES192WithCBC(DEFAULT_IV128, RANDOM_192_BITS());
    }

    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithSHAAnd3KeyTripleDES(String password) throws CryptoException {
        return new SK(
                new PBEAlgorithm(Algorithm.SHA1, Algorithm.DESede),
                new PBEParameterSpec(DEFAULT_SALT, DEFAULT_COUNT),
                password
        );
    }

    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithMD5AndTripleDES(String password) throws CryptoException {
        return new SK(
            new PBEAlgorithm(Algorithm.MD5, Algorithm.DESede),
            new PBEParameterSpec(DEFAULT_SALT, DEFAULT_COUNT), password
        );
    }
    
    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithMD5AndDES(String password) throws CryptoException {
        return new SK(
                new PBEAlgorithm(Algorithm.MD5, Algorithm.DES),
                new PBEParameterSpec(DEFAULT_SALT, DEFAULT_COUNT), password
        );
    }

    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithSHA256And256BitAES(String password) throws CryptoException {
        return new SK(
            new PBEAlgorithm(Algorithm.SHA256, Algorithm.AES, 256),
            new PBEParameterSpec(DEFAULT_SALT, DEFAULT_COUNT), password
        );
    }
    
    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithSHA1AndDESede(String password) throws CryptoException {
        return new SK(
            new PBEAlgorithm(Algorithm.SHA1, Algorithm.DESede),
            new PBEParameterSpec(DEFAULT_SALT, DEFAULT_COUNT), password
        );
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
     * Verifies size of byte array
     * 
     * @param array
     * @param size expected size in bits
     * @throws CryptoException 
     */
    static private void VERIFY_IV_BIT_SIZE(final byte[] array, int size) throws CryptoException {
        if (array == null || array.length !=  (size / 8)) {
            throw new CryptoException("IV must " + size + " bits");
        }
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
    static private SecretKeySpec KEY_BIT_CHECK(final byte[] key, final Algorithm algorithm, final int size) 
            throws CryptoException {
        
        if (key==null){
            switch(size){
                case 64:
                case 128:
                case 192:
                case 256:
                    return new SecretKeySpec(RANDOM_BITS(size), algorithm.name());

                default:
                    throw new CryptoException("Illeagel IV bit size " + size);
            }            
        } else if (key.length !=  (size / 8)){
            throw new CryptoException("key must " + size + " bits");
        }
        
        return new SecretKeySpec(key, algorithm.name());
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
    static private SecretKeySpec KEY128_BIT_CHECK(byte[] key, Algorithm algorithm) throws CryptoException {
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
    static private SecretKeySpec KEY192_BIT_CHECK(byte[] key, Algorithm algorithm) throws CryptoException {
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
    static private SecretKeySpec KEY256_BIT_CHECK(byte[] key, Algorithm algorithm) throws CryptoException {
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

    static final private byte[] DEFAULT_SALT = {
        (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
        (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
    };

    // Iteration count
    static final private int DEFAULT_COUNT = 20;    
    
    /**
     * SecureRandom
     */
    final static private SecureRandom SECURE_RANDOM = new SecureRandom();    
}