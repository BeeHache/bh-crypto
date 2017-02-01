/*
 * The MIT License
 *
 * Copyright 2017 Benjamin King aka Blackhacker(bh@blackhacker.net)
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

import net.blackhacker.crypto.algorithm.SymetricAlgorithm;
import net.blackhacker.crypto.algorithm.Mode;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import net.blackhacker.crypto.algorithm.AsymetricAlgorithm;

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
                new Transformation(AsymetricAlgorithm.RSA, Mode.ECB));
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
                new Transformation(AsymetricAlgorithm.RSA, Mode.ECB)
                ,publicKeyEncoded,privateKeyEncoded);
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
                new Transformation(AsymetricAlgorithm.RSA, Mode.ECB)
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.ECB));
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.ECB), key);
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.CBC));
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.CBC), key);
    } 
    
    /**
     * Factory method for generating an SK object using DES algorithm in CFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithCFB() throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.CFB));
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.CFB), key);
    }
    
    /**
     * Factory method for building an SK object using DES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESWithOFB() throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.OFB));
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
        return new SK(new Transformation(SymetricAlgorithm.DES, Mode.OFB), key);
    }
    
    
    /**
     * Factory method for building an SK object using Triple DES algorithm in ECB mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorDESedeWithECB() throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.ECB));
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
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.ECB), key);
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
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.CBC));
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
    final static public SK newEncryptorDESedeWithCBC(byte[] key) throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.CBC), key);
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
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.CFB));
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
    final static public SK newEncryptorDESedeWithCFB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymetricAlgorithm.DESede, Mode.CFB), key);
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
                new Transformation(SymetricAlgorithm.DESede, Mode.OFB));
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
    final static public SK newEncryptorDESedeWithOFB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymetricAlgorithm.DESede, Mode.OFB), key);
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
            new Transformation(SymetricAlgorithm.AES, Mode.ECB),key);
    }

    /**
     * Factory method for building an SK object using AES algorithm 
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithECB() throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.AES, Mode.ECB));
    }    
    
    
    /**
     * Factory method for building an SK object using AES algorithm in CBC mode
     *
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithCBC() throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.DESede, Mode.CBC));
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
    final static public SK newEncryptorAES128WithCBC(byte[] key) throws CryptoException {
        return new SK(new Transformation(SymetricAlgorithm.AES, Mode.CBC), key);
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
            new Transformation(SymetricAlgorithm.AES, Mode.CFB), key
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
            new Transformation(SymetricAlgorithm.AES, Mode.CFB));
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
    final static public SK newEncryptorAES128WithOFB(byte[] key) throws CryptoException {
        return new SK( new Transformation(SymetricAlgorithm.AES, Mode.OFB), key);
    }
    
    /**
     * Factory method for building an SK object using AES algorithm in OFB mode
     * 
     * @return SK Object
     * @throws CryptoException
     * @see SK
     */
    final static public SK newEncryptorAES128WithOFB() throws CryptoException {
        return new SK( new Transformation(SymetricAlgorithm.AES, Mode.OFB));
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
    final static public SK newEncryptorAES128WithCTR(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymetricAlgorithm.AES, Mode.CTR),key);
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
            new Transformation(SymetricAlgorithm.AES, Mode.CTR));
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
    final static public SK newEncryptorAES128WithOCB(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymetricAlgorithm.AES, Mode.OCB), key);
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
            new Transformation(SymetricAlgorithm.AES, Mode.OCB));
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
            new Transformation(SymetricAlgorithm.AES192, Mode.ECB), key);
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
            new Transformation(SymetricAlgorithm.AES192, Mode.ECB));
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
            new Transformation(SymetricAlgorithm.AES192, Mode.ECB));
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
    final static public SK newEncryptorAES192WithCBC(byte[] key) throws CryptoException {
        return new SK(
            new Transformation(SymetricAlgorithm.AES192, Mode.CBC), key);
    }
    
    

    /**
     *
     * @param password
     * @return
     * @throws CryptoException
     */
    final static public SK newEncryptorPBEWithSHAAnd3KeyTripleDES(String password) throws CryptoException {
        return new SK(
            new Transformation(DigestAlgorithm.SHA1, SymetricAlgorithm.DESede),
            password.toCharArray()
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
            new Transformation(DigestAlgorithm.MD5, SymetricAlgorithm.DESede),
            password.toCharArray()
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
            new Transformation(DigestAlgorithm.MD5, SymetricAlgorithm.DES),
            password.toCharArray()
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
            new Transformation(DigestAlgorithm.SHA256, SymetricAlgorithm.AES),
            password.toCharArray()
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
            new Transformation(DigestAlgorithm.SHA1, SymetricAlgorithm.DESede),
            password.toCharArray()
        );
    }  
}