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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

/**
 * Base class for all implementations of Asymmetric (Public Key) Encryption
 * 
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 * @see java.security.PrivateKey
 * @see java.security.PublicKey
 */
public class PK extends Crypto {
    final private PublicKey publicKey;
    final private PrivateKey privateKey;
    
    /**
     * Constructor build public and private keys from the parameterSpec, and the
     * encoded keys
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation,
            final byte[] publicKeyEncoded, final byte[] privateKeyEncoded)
            throws CryptoException {
        super(transformation);
        Validator.notNull(transformation, "transformation");
        Validator.notNull(publicKeyEncoded, "publicKeyEncoded");
        Validator.notNull(privateKeyEncoded, "privateKeyEncoded");
        try {
            KeyFactory kf = KeyFactory.getInstance(transformation.getAlgorithmString());
            
            publicKey = kf.generatePublic(
                    new X509EncodedKeySpec(publicKeyEncoded));
            
            privateKey = kf.generatePrivate(
                    new PKCS8EncodedKeySpec(privateKeyEncoded));
        } catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Constructor build public and private keys from the parameterSpec, and the
     * encoded keys
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation, final byte[] publicKeyEncoded)
            throws CryptoException {
        super(transformation);
        Validator.notNull(publicKeyEncoded, "publicKeyEncoded");
        try {
            KeyFactory kf = KeyFactory.getInstance(transformation.getAlgorithmString());
            
            publicKey = kf.generatePublic(
                    new X509EncodedKeySpec(publicKeyEncoded));
            
            privateKey = null;
        } catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }
    
    /**
     * Constructor build public and private keys from the parameterSpec, and the
     * encoded keys
     * 
     * @param transformation
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation) throws CryptoException {
        super(transformation);
        
        try {
            KeyPairGenerator kpg = KeyPairGenerator
                    .getInstance(transformation.getAlgorithmString());
            kpg.initialize(transformation.getKeySize(), getSecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
        } catch(NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }

    
    /**
     * Encrypts array of bytes
     * 
     * @param clearBytes
     * @param parameters
     * @return encrypted version of clearBytes
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] clearBytes, Object... parameters) throws CryptoException {
        Validator.notNull(clearBytes, "clearBytes");
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        AlgorithmParameterSpec aps = processParameters(parameters);
        try {
            synchronized (cipher) {
                if (aps!=null) {
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, aps, secureRandom);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, secureRandom);
                }
            }
            return cipher.doFinal(clearBytes);
        } catch (InvalidKeyException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException |
                BadPaddingException ex) {
            throw new CryptoException(
                    String.format(Strings.COULDNT_ENCRYPT_MSG, 
                            getTransformation(),
                            ex.getLocalizedMessage()) ,ex);
        }
    }
    
    /**
     * Decrypts array of bytes
     * 
     * @param cipherBytes
     * @param parameters
     * @return clear version of cipherBytes
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] cipherBytes, Object... parameters) throws CryptoException {
        Validator.notNull(cipherBytes, "cipherBytes");
        if (privateKey==null){
            throw new CryptoException("No PrivateKey defined");
        }
        
        Transformation transformation = getTransformation();
        
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        AlgorithmParameterSpec aps = processParameters(parameters);
        
        try {
            synchronized(cipher) {
                if (aps!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, privateKey, aps, secureRandom);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, privateKey, secureRandom);
                }

                return cipher.doFinal(cipherBytes);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | 
                IllegalBlockSizeException | BadPaddingException ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_DECRYPT_MSG, 
                        transformation.toString(),
                        ex.getLocalizedMessage()),ex);
        }
    }
    
    /**
     * 
     * @return
     */
    public Verifier getVerifier() {
        return getVerifier(null);
    }

    /**
     *
     * @param digester
     * @return
     */
    public Verifier getVerifier(final Digester digester) {
        Validator.notNull(digester, "digester");
        Transformation transformation = getTransformation();
        
        final Cipher cipher = getCipher();
        return (final byte[] data, final byte[] signature) -> {
            synchronized(cipher) {
                int ivSize = 0;
                byte[] digest = digester==null ? null : digester.digest(data);
                try(ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
                    if (getTransformation().hasIV()) {
                        byte[] iv = transformation.readIV(bais);
                        cipher.init(Cipher.DECRYPT_MODE, publicKey, new IvParameterSpec(iv));
                    } else {
                        cipher.init(Cipher.DECRYPT_MODE, publicKey);
                    }
                
                    byte[]clearSig = cipher.doFinal(signature, transformation.getBlockSizeBytes(), signature.length);
                    return Arrays.equals(clearSig, digest);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException | IOException ex) {
                    return false;
                }
            }
        };
    }

    /**
     *
     * @return
     * @throws CryptoException
     */
    public Signer getSigner() throws CryptoException {
        return getSigner(null);
    }
    
    /**
     *
     * @param digester
     * @return
     * @throws CryptoException
     */
    public Signer getSigner(final Digester digester) throws CryptoException {
        Validator.notNull(digester, "digester");
        Validator.notNull(privateKey, "privateKey");
        
        final Cipher cipher = getCipher();
        final SecureRandom secureRandom = getSecureRandom();
        final Transformation transformation = getTransformation();
        
        return (final byte[] data) -> {
            Validator.notNull(data, "data");
            synchronized(cipher) {
                try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    byte[] digest = digester.digest(data);
                    
                    if (transformation.hasIV()) {
                        byte[] iv = transformation.generateIV(secureRandom);
                        baos.write(iv);
                        cipher.init(Cipher.ENCRYPT_MODE, privateKey, new IvParameterSpec(iv));
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    }
                    baos.write(cipher.doFinal(digest));
                    return baos.toByteArray();
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException |
                        IOException ex) {
                    throw new SignerException(
                            "Could not sign data: " + ex.getLocalizedMessage(),ex);
                }
            }
        };        
    }
    

    /**
     * Gets internal PubicKey object
     * 
     * @return PublicKey
     * @see PublicKey
     */
    final public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Gets internal PrivateKey object
     * 
     * @return PrivateKey
     * @see PrivateKey
     */
    final public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    final public byte[] getPublicKeyEncoded() {
        return publicKey.getEncoded();
    }
    
    final public byte[] getPrivateKeyEncoded() {
        return privateKey == null ? null : privateKey.getEncoded();
    }
}