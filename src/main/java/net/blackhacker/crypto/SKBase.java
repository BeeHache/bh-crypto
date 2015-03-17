package net.blackhacker.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ben
 */
public class SKBase extends Crypto {
    final private Key key;

    protected  SKBase(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
        super(cipherAlgorithm,algorithmParameterSpec);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(keyAlgorithm);
            kg.init(getSecureRandom());
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory",e);
        }
    }    
    
    protected SKBase(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec, KeySpec spec) throws CryptoException {
        super(cipherAlgorithm, algorithmParameterSpec);
        try {
            key = SecretKeyFactory.getInstance(keyAlgorithm).generateSecret(spec);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("Couldn't create key factory: " + ex.getLocalizedMessage(),ex);
        } catch (InvalidKeySpecException ex) {
            throw new CryptoException("Couldn't create key factory: " + ex.getLocalizedMessage(),ex);
        }
    }

    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithECB() throws CryptoException {
        return new SKBase("DES/ECB/PKCS5Padding", "DES", null);
    }

    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithECB(byte[] key) throws CryptoException {
        try {
            return new SKBase("DES/ECB/PKCS5Padding", "DES", null, new DESKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithCBC(byte[] iv) throws CryptoException {
        return new SKBase("DES/CBC/PKCS5Padding", "DES", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithCBC(byte[] iv, byte[]key) throws CryptoException {
        try {
            return new SKBase(
                    "DES/CBC/PKCS5Padding",
                    "DES",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                    new DESKeySpec(key)
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
    final static public SKBase getInstanceDESWithCBC() throws CryptoException {
        return SKBase.getInstanceDESWithCBC(IV8());
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithCFB(byte[] iv) throws CryptoException {
        return new SKBase("DES/CFB/PKCS5Padding", "DES", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SKBase(
                    "DES/CFB/PKCS5Padding",
                    "DES",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                    new DESKeySpec(key)
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
    final static public SKBase getInstanceDESWithCFB() throws CryptoException {
        return SKBase.getInstanceDESWithCFB(IV8());
    }    

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithOFB(byte[] iv) throws CryptoException {
        return new SKBase("DES/OFB/PKCS5Padding", "DES", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SKBase(
                    "DES/OFB/PKCS5Padding",
                    "DES",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                    new DESKeySpec(key)
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
    final static public SKBase getInstanceDESWithOFB() throws CryptoException {
        return SKBase.getInstanceDESWithOFB(IV8());
    }
    
    
     /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithECB() throws CryptoException {
        return new SKBase("DESede/ECB/PKCS5Padding", "DESede", null);
    }

     /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithECB(byte[] key) throws CryptoException {
        try {
            return new SKBase("DESede/ECB/PKCS5Padding", "DESede", null, new DESedeKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithCBC(byte[] iv) throws CryptoException {
        return new SKBase("DESede/CBC/PKCS5Padding", "DESede", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithCBC(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SKBase(
                    "DESede/CBC/PKCS5Padding",
                    "DESede",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
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
    final static public SKBase getInstanceDESedeWithCBC() throws CryptoException {
        return SKBase.getInstanceDESedeWithCBC(IV8());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithCFB(byte[] iv) throws CryptoException {
        return new SKBase("DESede/CFB/PKCS5Padding", "DESede", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SKBase(
                    "DESede/CFB/PKCS5Padding",
                    "DESede",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
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
    final static public SKBase getInstanceDESedeWithCFB() throws CryptoException {
        return SKBase.getInstanceDESedeWithCFB(IV8());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithOFB(byte[] iv) throws CryptoException {
        return new SKBase("DESede/OFB/PKCS5Padding", "DESede", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceDESedeWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SKBase(
                    "DESede/OFB/PKCS5Padding",
                    "DESede",
                    new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
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
    final static public SKBase getInstanceDESedeWithOFB() throws CryptoException {
        return SKBase.getInstanceDESedeWithOFB(IV8());
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceAESWithCBC(byte[] iv) throws CryptoException {
        return new SKBase(
                "AES/CBC/PKCS5Padding", 
                "AES", 
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv)
        );
    }
    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceAESWithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SKBase(
                "AES/CBC/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES/CBC/PKCS5Padding")
        );
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SKBase getInstanceAESWithCBC() throws CryptoException {
        return SKBase.getInstanceAESWithCBC(IV16());
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
        Cipher cipher = getCipher();
        
        synchronized(this) {
            try {
                if (param !=null) {
                    cipher.init(Cipher.ENCRYPT_MODE, key, param);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                }
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException(ex);
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
        Cipher cipher = getCipher();
        
        synchronized(this) {
            try {
                if (param!=null) {
                    cipher.init(Cipher.DECRYPT_MODE, getKey(), param);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, getKey());
                }
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    public Key getKey() throws CryptoException {
        return key;
    }
    
    public byte[] getKeyEncoded() {
        return key.getEncoded();
    }
    
    static private SecureRandom sr = new SecureRandom();
    
    static private byte[] IV8() {
        byte[] iv = new byte[8];
        sr.nextBytes(iv);
        return iv;
    }

    static private byte[] IV16() {
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        return iv;
    }
}