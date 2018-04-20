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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;

/**
 * Base class for all implementations of Asymmetric (Public Key) Encryption
 * 
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 * @see java.security.PrivateKey
 * @see java.security.PublicKey
 */
public class PK extends Crypto implements Encryptor, Decryptor {
    final private PublicKey publicKey;
    final private PrivateKey privateKey;
    final private Signature signer;
    
    static final public Digester DEFAULT_DIGESTER 
        = DigesterFactory.newDigesterMD5();
    
    static final private DigestAlgorithm DEFALT_DIGEST_ALGORYTHM =
            DigestAlgorithm.MD5;
    
    /**
     * Constructor initializes from from the encoded keys
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    
    public PK(final Transformation transformation,
            final byte[] publicKeyEncoded, final byte[] privateKeyEncoded) throws CryptoException{
        this(Validator.notNull(transformation, "transformation"), 
             Validator.notNull(publicKeyEncoded, "publicKeyEncoded"), 
             Validator.notNull(privateKeyEncoded, "privateKeyEncoded"), 
             DEFALT_DIGEST_ALGORYTHM);
    }
    
    /**
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @param digestAlgorithm
     * @throws CryptoException 
     */
    private PK(final Transformation transformation,
            final byte[] publicKeyEncoded, final byte[] privateKeyEncoded,
            final DigestAlgorithm digestAlgorithm)
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
            signer = Signature.getInstance(digestAlgorithm.name() +"with" + transformation.getAsymmetricAlgorithm());
            
        } catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Initializes from an encoded public key. Object initialized this was can 
     * only encrypt data, and not decrypt 
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @param digestAlgorithm
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation, final byte[] publicKeyEncoded,
    DigestAlgorithm digestAlgorithm)
            throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
                Validator.notNull(publicKeyEncoded, "publicKeyEncoded"),
                null, 
                Validator.notNull(digestAlgorithm, "digestAlgorithm"));
    }
    
    public PK(final Transformation transformation, final byte[] publicKeyEncoded) throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
                Validator.notNull(publicKeyEncoded, "publicKeyEncoded"), 
                null, DEFALT_DIGEST_ALGORYTHM);
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
        this(Validator.notNull(transformation, "transformation"), 
                null, null, DEFALT_DIGEST_ALGORYTHM);
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
                    return Utils.concat(iv, cipherbytes);
                }
                return cipherbytes;
            }
        } catch (BadPaddingException ex) {
            return null;
        } catch (InvalidKeyException | IllegalBlockSizeException | 
                InvalidAlgorithmParameterException ex) {
            throw new CryptoException(
                    String.format(Strings.COULDNT_ENCRYPT_MSG_FMT, 
                            getTransformation(),
                            ex.getLocalizedMessage()), 
                    ex);
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
        byte[] cipherBytes = data;
        
        if (hasIV()) {
            byte[] iv = new byte[getBlockSizeBytes()];
            cipherBytes = new byte[data.length - iv.length];
            Utils.split(data, iv, cipherBytes);
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
     * 
     * @param data
     * @return 
     * @throws net.blackhacker.crypto.CryptoException 
     */
    public byte[] sign(byte[] data) throws CryptoException {
        return _sign(Validator.notNull(data, "data"), 0, data.length);
    }
    
    /**
     * 
     * @param data
     * @param pos
     * @param len
     * @return
     * @throws CryptoException 
     */
    public byte[] sign(byte[] data, int pos, int len) throws CryptoException {
        return _sign(Validator.notNull(data, "data"),
              Validator.gte(pos,0, "pos"),
              Validator.lte(len, data.length-pos, "len")
        );
    }
    
    private byte[] _sign(byte[] data, int pos, int len) throws CryptoException {
        try {
            synchronized(signer) {
                signer.initSign(privateKey, getSecureRandom());
                signer.update(data, pos, len);
                return signer.sign();
            }
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CryptoException(
                        "Could not sign data: " + ex.getLocalizedMessage(),ex);
        }
    }
    /**
     * 
     * @param data
     * @param signature
     * @return
     * @throws CryptoException 
     */
    public boolean verify(byte[] data, byte[] signature) throws CryptoException{
        return verify(
                Validator.notNull(data, "data"),0,data.length, 
                Validator.notNull(signature, "signature"),0, signature.length);
    }
    /**
     * 
     * @param data
     * @param dataOffset
     * @param dataLength
     * @param signature
     * @param sigOffset
     * @param sigLength
     * @return
     * @throws CryptoException 
     */
    public boolean verify(byte[] data, int dataOffset, int dataLength, byte[] signature, int sigOffset, int sigLength) throws CryptoException{
        return _verify(
            Validator.notNull(data, "data"),
            Validator.gte(dataOffset,0, "dataOffset"),
            Validator.lte(dataLength, data.length-dataOffset, "dataLength"),
            Validator.notNull(signature, "signature"),
            Validator.gte(sigOffset,0, "sigOffset"),
            Validator.lte(sigLength, signature.length-sigOffset, "sigLength"));
    }
    
    
    public boolean _verify(byte[] data, int dataOffset, int dataLength, byte[] signature, int sigOffset, int sigLength) throws CryptoException {
        try {
            synchronized(signer) {
                signer.initVerify(publicKey);
                signer.update(data, dataOffset, dataLength);
                return signer.verify(signature, sigOffset, sigLength);
            }
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CryptoException(
                        "Could not verify signature: " + ex.getLocalizedMessage(),ex);
        }
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