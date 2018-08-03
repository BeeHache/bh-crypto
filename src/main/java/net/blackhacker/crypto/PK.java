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

import java.io.IOException;
import java.math.BigInteger;
import net.blackhacker.crypto.utils.Utils;
import net.blackhacker.crypto.utils.Validator;
import java.security.cert.Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import net.blackhacker.crypto.algorithm.DigestAlgorithm;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

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
    final private String name;
    
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
     * @param name
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation,
            final byte[] publicKeyEncoded, 
            final byte[] privateKeyEncoded,
            final String name) throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
             Validator.notNull(publicKeyEncoded, "publicKeyEncoded"), 
             Validator.notNull(privateKeyEncoded, "privateKeyEncoded"), 
             DEFALT_DIGEST_ALGORYTHM,
             name);
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
            final byte[] publicKeyEncoded, 
            final byte[] privateKeyEncoded,
            final DigestAlgorithm digestAlgorithm,
            final String name)
            throws CryptoException {
        super(transformation);
        this.name = name;
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
            throw new CryptoException("", e);
        }
    }

    /**
     * Initializes from an encoded public key. Object initialized this was can 
     * only encrypt data, and not decrypt 
     * 
     * @param transformation
     * @param publicKeyEncoded
     * @param digestAlgorithm
     * @param name
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation, final byte[] publicKeyEncoded,
    DigestAlgorithm digestAlgorithm,  String name)
            throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
             Validator.notNull(publicKeyEncoded, "publicKeyEncoded"),
             null, 
             Validator.notNull(digestAlgorithm, "digestAlgorithm"),
             name);
    }
    
    public PK(final Transformation transformation, 
              final byte[] publicKeyEncoded,
              final String name) throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
             Validator.notNull(publicKeyEncoded, "publicKeyEncoded"), 
             null, 
             DEFALT_DIGEST_ALGORYTHM,
             name);
    }
    
    /**
     * Constructor build public and private keys from the parameterSpec, and the
     * encoded keys
     * 
     * @param transformation
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public PK(final Transformation transformation, final String name) throws CryptoException {
        this(Validator.notNull(transformation, "transformation"), 
             null, 
             null, 
             DEFALT_DIGEST_ALGORYTHM,
             name);
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
        return _encrypt(Validator.notNull(clearBytes, "clearBytes"), 0, clearBytes.length);
    }
    
    /**
     * 
     * @param clearBytes
     * @param offset
     * @param length
     * @return
     * @throws CryptoException 
     */
    @Override
    public byte[] encrypt(final byte[] clearBytes, int offset, int length) throws CryptoException {
        return _encrypt(
                Validator.notNull(clearBytes, "clearBytes"),
                Validator.gte(offset, 0, "offset"), 
                Validator.lte(length, clearBytes.length, "length"));
    }
    
/**
 * 
 * @param clearBytes
 * @param offset
 * @param length
 * @return
 * @throws CryptoException 
 */
 private byte[] _encrypt(final byte[] clearBytes, int offset, int length) throws CryptoException {
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
                
                byte[] cipherbytes = cipher.doFinal(clearBytes,offset, length);
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
     * Decrypts an encrypted byte array
     * 
     * @param data encrypted byte array
     * @return clear version of data
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data) throws CryptoException {
        Validator.notNull(data, "data");
        return _decrypt(data, 0, data.length);
    }
    
    /**
     * 
     * @param data
     * @param offset
     * @param length
     * @return
     * @throws CryptoException 
     */
    @Override
    public byte[] decrypt(final byte[] data, int offset, int length) throws CryptoException {
        Validator.notNull(data, "data");
        Validator.gte(offset, 0, "offset");
        Validator.lte(length, data.length, "length");
        return _decrypt(data, offset, length);
    }
 
 
    /**
     * Decrypts array of bytes
     * 
     * @param data
     * @param offset
     * @param length
     * @return clear version of cipherBytes
     * @throws CryptoException 
     */
    private byte[] _decrypt(final byte[] data, int offset, int length) throws CryptoException {

        if (privateKey==null){
            throw new CryptoException("No PrivateKey defined");
        }
        
        Cipher cipher = getCipher();
        SecureRandom secureRandom = getSecureRandom();
        AlgorithmParameterSpec aps = null;
        byte[] cipherBytes = data;
        
        if (hasIV()) {
            byte[] iv = new byte[getBlockSizeBytes()];
            cipherBytes = new byte[length - iv.length];
            Utils.split(Arrays.copyOfRange(data, offset, offset + length), iv, cipherBytes);
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
    
    public Certificate signCertificate(Certificate cert) throws CryptoException {
        if("X509".equals(cert.getType())) {
            X509Certificate x509 = (X509Certificate)cert;
            String subject = x509.getSubjectX500Principal().getName();
            Date from = x509.getNotAfter();
            Date to = x509.getNotAfter();
            PublicKey publicKey = x509.getPublicKey();
            return _issueCertificate(subject, from, to, publicKey);
        }
        
        
        throw new RuntimeException();
    }
    
    
    public Certificate issueCertificate(String subject, int seconds, PublicKey publicKey) throws CryptoException {
        Date from = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(from);
        calendar.add(Calendar.SECOND, seconds); // <-- 1 Yr validity
        Date to = calendar.getTime();
        
        return _issueCertificate(subject, from, to, publicKey);
    }
    
    /**
     * 
     * @param days 
     */
    private  Certificate _issueCertificate(String subject, Date from, Date to, PublicKey publicKey) throws CryptoException {
        try {
            BigInteger sn = new BigInteger(64, getSecureRandom());

            X509CertInfo info = new X509CertInfo();            
            info.set(X509CertInfo.VALIDITY, new CertificateValidity(from, to));
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(new X500Name(subject)));
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName(new X500Name(name)));
            info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            
            //AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
            //AlgorithmId algo = AlgorithmId.get(signer.getAlgorithm());
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(signer.getAlgorithm())));
            //info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, AlgorithmId.get(signer.getAlgorithm()));
 
            // Sign the cert to identify the algorithm that's used.
            //X509CertImpl cert = new X509CertImpl(info);
            //cert.sign(getPrivateKey(), signer.getAlgorithm());
 
            // Update the algorith, and resign.
            //algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
            //info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
            X509CertImpl cert = new X509CertImpl(info);
            cert.sign(getPrivateKey(), signer.getAlgorithm());
            
            
            return cert;
            
        } catch (CertificateException | IOException | InvalidKeyException |
                 NoSuchProviderException | SignatureException | 
                 NoSuchAlgorithmException ex) {
            throw new CryptoException(
                        "Could not generate cert: " + ex.getLocalizedMessage(),ex);
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