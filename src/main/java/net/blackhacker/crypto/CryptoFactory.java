/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2017 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import net.blackhacker.crypto.algorithm.SymmetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import net.blackhacker.crypto.algorithm.AsymmetricAlgorithm;

/**
 *
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
final public class CryptoFactory {
    
    /**
     * Factory method for generating PK object using RSA
     * 
     * @return PK object
     * @throws CryptoException
     * @see PK
     */
    static public PK newEncryptorRSAWithECB() throws CryptoException {
        return new PK(
                new Transformation(AsymmetricAlgorithm.RSA1024, Mode.ECB));
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
                new Transformation(AsymmetricAlgorithm.RSA1024, Mode.ECB)
                ,publicKeyEncoded,privateKeyEncoded);
    }

    /**
     * Factory method for building PK object from public keys using RSA
     * 
     * @param publicKeyEncoded
     * @return PK object
     * @throws CryptoException
     * @see PK
     */
    static public PK newEncryptorRSAWithECB(final byte[] publicKeyEncoded) 
            throws CryptoException {
        return new PK(
                new Transformation(AsymmetricAlgorithm.RSA1024, Mode.ECB)
                ,publicKeyEncoded);
    }  

    /**
     * Factory method for generating SK object using DES algorithm in ECB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithECB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.ECB));
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
    final static public SK newEncryptorDESWithECB(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.ECB), key);
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
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.CBC));
    } 

    /**
     * Factory method for generating an SK object using DES algorithm in CBC 
     * mode with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCBC(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.CBC), key);
    } 
    
    /**
     * Factory method for generating an SK object using DES algorithm in CFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.CFB));
    }

    /**
     * Factory method for generating an SK object using DES algorithm in CFB mode
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.CFB), key);
    }
    
    /**
     * Factory method for building an SK object using DES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.OFB));
    }

    /**
     * Factory method for building an SK object using DES algorithm in OFB mode
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DES, Mode.OFB), key);
    }
    
    
    /**
     * Factory method for building an SK object using Triple DES algorithm in ECB mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithECB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.ECB));
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
    final static public SK newEncryptorDESedeWithECB(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.ECB), key);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in CBC mode with the given IV
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCBC() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.CBC));
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in CBS mode with the given IV
     *
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCBC(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.CBC), key);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in CFB mode with the given IV
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCFB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.CFB));
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in CFB mode with the given IV
     *
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithCFB(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.DESede, Mode.CFB), key);
    }
    
    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * in OFB mode with the given IV
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithOFB() throws CryptoException {
        return new SK(
                new Transformation(SymmetricAlgorithm.DESede, Mode.OFB));
    }

    /**
     * Factory method for building an SK object using Triple DES algorithm 
     * from encoded key in OFB mode with the given IV
     *
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithOFB(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.DESede, Mode.OFB), key);
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
    final static public SK newEncryptorAES128WithECB(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.ECB),key);
    }

    /**
     * Factory method for building an SK object using AES algorithm 
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithECB() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.AES, Mode.ECB));
    }    
    
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC() throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.DESede, Mode.CBC));
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC(final byte[] key) throws CryptoException {
        return new SK(new Transformation(SymmetricAlgorithm.AES, Mode.CBC), key);
    }

    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCFB(final byte[] key) 
            throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.CFB), key
        );
    }

    /**
     * Factory method for building an SK object using AES algorithm in CFB mode
     * with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCFB() throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.CFB));
    }

    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB(final byte[] key) throws CryptoException {
        return new SK( new Transformation(SymmetricAlgorithm.AES, Mode.OFB), key);
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB() throws CryptoException {
        return new SK( new Transformation(SymmetricAlgorithm.AES, Mode.OFB));
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CTR mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCTR(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.CTR),key);
    }

    /**
     * Factory method for building an SK object using AES algorithm in CTR mode
     * from encoded key with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCTR() throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.CTR));
    }    

    /**
     * Factory method for building an SK object using AES algorithm in OCB mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOCB(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.OCB), key);
    }

    /**
     * Factory method for building an SK object using AES algorithm in OCB mode
     * from encoded key
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOCB() throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES, Mode.OCB));
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
    final static public SK newEncryptorAES192WithECB(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES192, Mode.ECB), key);
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
        return new SK(
            new Transformation(SymmetricAlgorithm.AES192, Mode.ECB));
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *  with the given IV
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithCBC() throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES192, Mode.ECB));
    }

    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     * from encoded key with the given IV
     * 
     * @param key
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES192WithCBC(final byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymmetricAlgorithm.AES192, Mode.CBC), key);
    }
    
    

    /**
     * Builds a new Password Based Encryption (PBE) enabled SK object based on
     * the given password
     * 
     * @param password
     * @return SK
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorPBEWithSHAAnd3KeyTripleDES(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.SHA1, SymmetricAlgorithm.DESede),
            password.toCharArray()
        );
    }

    /**
     * Builds a new Password Based Encryption (PBE) enabled SK object based on
     * the given password
     * 
     * @param password
     * @return SK object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorPBEWithMD5AndTripleDES(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.MD5, SymmetricAlgorithm.DESede),
            password.toCharArray()
        );
    }
    
    /**
     * Builds a new Password Based Encryption (PBE) enabled SK object based on
     * the given password
     * 
     * @param password
     * @return SK object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorPBEWithMD5AndDES(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.MD5, SymmetricAlgorithm.DES),
            password.toCharArray()
        );
    }

    /**
     * Builds a new Password Based Encryption (PBE) enabled SK object based on
     * the given password
     * 
     * @param password
     * @return SK object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorPBEWithSHA256And256BitAES(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.SHA256, SymmetricAlgorithm.AES),
            password.toCharArray()
        );
    }
    
    /**
     * Builds a new Password Based Encryption (PBE) enabled SK object based on
     * the given password
     * 
     * @param password
     * @return SK object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorPBEWithSHA1AndDESede(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.SHA1, SymmetricAlgorithm.DESede),
            password.toCharArray()
        );
    }  
}