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
    
    static final public Digester DEFAULT_DIGESTER;
    
    static {
        DEFAULT_DIGESTER = DigesterFactory.newDigesterMD5();
    }
    
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
        PublicKey pu;
        PrivateKey pr;
        
        try {
            KeyFactory kf = KeyFactory
                    .getInstance(transformation.getAlgorithmString());
            
            pu = publicKeyEncoded!=null 
                    ? kf.generatePublic(transformation.makePublicKeySpec(publicKeyEncoded)) 
                    : null;
            
            pr = privateKeyEncoded!=null 
                    ? kf.generatePrivate(transformation.makePrivateKeySpec(privateKeyEncoded)) 
                    : null;
            
            if (pu==null && pr==null) {
                KeyPairGenerator kpg = KeyPairGenerator
                        .getInstance(transformation.getAlgorithmString());
                kpg.initialize(transformation.getKeySize(), getSecureRandom());
                KeyPair kp = kpg.generateKeyPair();
                pu = kp.getPublic();
                pr = kp.getPrivate();                
            }
            
            publicKey = pu;
            privateKey = pr;
            
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
        this(transformation, publicKeyEncoded, null);
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
        this(transformation, null, null);
    }

    
    /**
     * Encrypts array of bytes
     * 
     * @param clearBytes
     * @return encrypted version of clearBytes
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(final byte[] clearBytes) throws CryptoException {
        Validator.notNull(clearBytes, "clearBytes");
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        AlgorithmParameterSpec aps = null;
        byte[] iv = null;
        
        if (hasIV()) {
            iv = generateIV();
            aps = makeParameterSpec(iv);
        }
        
        
        try {
            synchronized (cipher) {
                if (aps!=null) {
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, aps, secureRandom);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, secureRandom);
                }
                
                byte[] cipherbytes = cipher.doFinal(clearBytes);
                if (iv!=null) {
                    return concat(iv, cipherbytes);
                }
                return cipherbytes;
            }
        } catch (InvalidKeyException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException |
                BadPaddingException ex) {
            throw new CryptoException(
                    String.format(Strings.COULDNT_ENCRYPT_MSG_FMT, 
                            getTransformation(),
                            ex.getLocalizedMessage()) ,ex);
        }
    }
    
    /**
     * Decrypts array of bytes
     * 
     * @param data
     * @return clear version of cipherBytes
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "cipherBytes");
        if (privateKey==null){
            throw new CryptoException("No PrivateKey defined");
        }
        
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        AlgorithmParameterSpec aps = null;
        byte[] iv = null;
        byte[] cipherBytes = data;
        
        if (hasIV()) {
            iv = new byte[getBlockSizeBytes()];
            cipherBytes = new byte[data.length - iv.length];
            split(data, iv, cipherBytes);
            aps = makeParameterSpec(iv);  
        }
        
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
                String.format(Strings.COULDNT_DECRYPT_MSG_FMT,
                        getTransformation(),
                        ex.getLocalizedMessage()),ex);
        }
    }
    
    /**
     * Builds a new Verifier based on this PK object and the DEFAULT_DIGESTER
     * 
     * @return new Verifier object
     * @see Verifier
     */
    public Verifier getVerifier() {
        return getVerifier(DEFAULT_DIGESTER);
    }

    /**
     * Builds a new Verifier based on this PK object and the given Digester
     * 
     * @param digester
     * @return new Verifier object
     * @see Verifier
     */
    public Verifier getVerifier(final Digester digester) {
        Validator.notNull(digester, "digester");
        
        final Transformation transformation = getTransformation();
        final Cipher cipher = getCipher();
        
        return (final byte[] data, final byte[] signature) -> {
            AlgorithmParameterSpec aps = null;
            byte[] cipherBytes = data;
            
            if (transformation.hasIV()) {
                byte[] iv = new byte[transformation.getBlockSizeBytes()];
                cipherBytes = new byte[data.length - iv.length];
                Crypto.split(data, iv, cipherBytes);
                aps = new IvParameterSpec(iv);
            }
            
            synchronized(cipher) {
                byte[] digest = digester.digest(data);
                try {
                    if (aps!=null) {
                        cipher.init(Cipher.DECRYPT_MODE, publicKey, aps);
                    } else {
                        cipher.init(Cipher.DECRYPT_MODE, publicKey);
                    }
                
                    byte[]clearSig = cipher.doFinal(signature);
                    return Arrays.equals(clearSig, digest);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException ex) {
                    return false;
                }
            }
        };
    }

    /**
     * Builds a new Signer based on this PK object and the DEAULT_DIGESTER
     * 
     * @return Signer
     * @throws CryptoException
     * @see Signer
     */
    public Signer getSigner() throws CryptoException {
        return getSigner(DEFAULT_DIGESTER);
    }
    
    /**
     * Builds a new Signer based on this PK object and the given Digester
     * 
     * @param digester
     * @return a new Signer object
     * @throws CryptoException
     */
    public Signer getSigner(final Digester digester) throws CryptoException {
        Validator.notNull(digester, "digester");
        Validator.notNull(privateKey, "privateKey");
        
        final Cipher cipher = getCipher();
        
        return (final byte[] data) -> {
            Validator.notNull(data, "data");
            AlgorithmParameterSpec aps = null;
            byte[] iv = null;
            
            if (getTransformation().hasIV()){
                aps = new IvParameterSpec(generateIV());
            }
            
            byte[] digest = digester.digest(data);
            
            synchronized(cipher) {
                try {
                    if (aps!=null) {
                        cipher.init(Cipher.ENCRYPT_MODE, privateKey, aps);
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                    }

                    byte[] cipherBytes = cipher.doFinal(digest);
                    return Crypto.concat(iv, cipherBytes);                    
                    
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException ex) {
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
    
    /**
     * PublicKey encoded into a byte array
     * 
     * @return encoded PublicKey
     * @see PublicKey
     */
    final public byte[] getPublicKeyEncoded() {
        return publicKey.getEncoded();
    }
    
    /**
     * PrivateKey encoded into a byte array
     * 
     * @return encoded PrivateKey
     * @see PrivateKey
     */
    final public byte[] getPrivateKeyEncoded() {
        return privateKey == null ? null : privateKey.getEncoded();
    }
}