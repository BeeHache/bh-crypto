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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

/**
 *
 * @author ben
 */
abstract public class PK extends Encryptor {
    final private PublicKey publicKey;
    final private PrivateKey privateKey;
    
    public  PK(String algorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
        super(algorithm, algorithmParameterSpec);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();        
            publicKey = kp.getPublic();
            privateKey = kp.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }
    
    /**
     *
     * @param algorithm
     * @param algorithmParameterSpec
     * @param publicKeyEncoded
     * @param privateKeyEncoded
     * @throws net.blackhacker.crypto.CryptoException
     */
    public PK(String algorithm, AlgorithmParameterSpec algorithmParameterSpec, byte[] publicKeyEncoded, byte[] privateKeyEncoded) throws CryptoException {
        super(algorithm, algorithmParameterSpec);
        try {
            EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyEncoded);
            EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
            KeyFactory kf = KeyFactory.getInstance(getAlgorithm());
            publicKey = kf.generatePublic(pubSpec);
            privateKey = kf.generatePrivate(privSpec);
        } catch(Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     *
     * @param data
     * @return
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        AlgorithmParameterSpec param = getAlgorithmParameterSpec();
        synchronized(getCipher()) {
            try {
                if (param !=null) {
                    getCipher().init(Cipher.ENCRYPT_MODE, publicKey, param);
                } else {
                    getCipher().init(Cipher.ENCRYPT_MODE, publicKey);
                }
                return getCipher().doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    /**
     * 
     * @param data
     * @return
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        AlgorithmParameterSpec param = getAlgorithmParameterSpec();
        synchronized(getCipher()) {
            try {
                if (param!=null) {
                    getCipher().init(Cipher.DECRYPT_MODE, privateKey, param);
                } else {
                    getCipher().init(Cipher.DECRYPT_MODE, privateKey);
                }
                return getCipher().doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public byte[] getPublicKeyEncoded() {
        return publicKey.getEncoded();
    }
    
    public byte[] getPrivateKeyEncoded() {
        return privateKey.getEncoded();
    }
}