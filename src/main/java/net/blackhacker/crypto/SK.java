package net.blackhacker.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

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
public class SK extends Crypto {
    final private Key key;

    private SK(String cipherAlgorithm, String keyAlgorithm, int keySize) throws CryptoException {
        super(cipherAlgorithm,null);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(keyAlgorithm);
            kg.init(keySize);
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory",e);
        }
    }
    
    private SK(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec) throws CryptoException {
        super(cipherAlgorithm,algorithmParameterSpec);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(keyAlgorithm);
            kg.init(getSecureRandom());
            key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Couldn't create key factory",e);
        }
    }
    
    private SK(String cipherAlgorithm, String keyAlgorithm, AlgorithmParameterSpec algorithmParameterSpec, KeySpec spec) throws CryptoException {
        super(cipherAlgorithm, algorithmParameterSpec);
        try {
            if (spec instanceof SecretKeySpec) {
                key = (Key) spec;
            } else {
                key = SecretKeyFactory.getInstance(keyAlgorithm).generateSecret(spec);
            }
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
    final static public SK getInstanceDESWithECB() throws CryptoException {
        return new SK("DES/ECB/PKCS5Padding", "DES", null);
    }

    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithECB(byte[] key) throws CryptoException {
        try {
            return new SK("DES/ECB/PKCS5Padding", "DES", null, new DESKeySpec(key));
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
    final static public SK getInstanceDESWithCBC(byte[] iv) throws CryptoException {
        return new SK(
                "DES/CBC/PKCS5Padding", 
                "DES", 
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
    final static public SK getInstanceDESWithCBC(byte[] iv, byte[]key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESWithCBC() throws CryptoException {
        return SK.getInstanceDESWithCBC(IV8());
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCFB(byte[] iv) throws CryptoException {
        return new SK(
                "DES/CFB/PKCS5Padding", 
                "DES", 
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
    final static public SK getInstanceDESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESWithCFB() throws CryptoException {
        return SK.getInstanceDESWithCFB(IV8());
    }    

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithOFB(byte[] iv) throws CryptoException {
        return new SK(
                "DES/OFB/PKCS5Padding", 
                "DES", 
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
    final static public SK getInstanceDESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESWithOFB() throws CryptoException {
        return SK.getInstanceDESWithOFB(IV8());
    }
    
    
     /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithECB() throws CryptoException {
        return new SK(
                "DESede/ECB/PKCS5Padding", 
                "DESede", 
                null
        );
    }

     /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithECB(byte[] key) throws CryptoException {
        try {
            return new SK(
                    "DESede/ECB/PKCS5Padding", 
                    "DESede", 
                    null, 
                    new DESedeKeySpec(key)
            );
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
    final static public SK getInstanceDESedeWithCBC(byte[] iv) throws CryptoException {
        return new SK(
                "DESede/CBC/PKCS5Padding", 
                "DESede", 
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
    final static public SK getInstanceDESedeWithCBC(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESedeWithCBC() throws CryptoException {
        return SK.getInstanceDESedeWithCBC(IV8());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithCFB(byte[] iv) throws CryptoException {
        return new SK(
                "DESede/CFB/PKCS5Padding", 
                "DESede", new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv)
        );
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESedeWithCFB() throws CryptoException {
        return SK.getInstanceDESedeWithCFB(IV8());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithOFB(byte[] iv) throws CryptoException {
        return new SK(
                "DESede/OFB/PKCS5Padding", 
                "DESede", 
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
    final static public SK getInstanceDESedeWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK(
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
    final static public SK getInstanceDESedeWithOFB() throws CryptoException {
        return SK.getInstanceDESedeWithOFB(IV8());
    }
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAESWithECB(byte[] key) throws CryptoException {
        return new SK(
                "AES/ECB/PKCS5Padding",
                "AES",
                null,
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithECB() throws CryptoException {
        return SK.getInstanceAESWithECB(KEY(128));
    }
    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAESWithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CBC/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCBC(byte[] iv) throws CryptoException {
        return SK.getInstanceAESWithCBC(iv, KEY(128));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCBC() throws CryptoException {
        return SK.getInstanceAESWithCBC(IV16(), KEY(128));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CFB/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCFB(byte[] iv) throws CryptoException {
        return SK.getInstanceAESWithCFB(iv, KEY(128));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCFB() throws CryptoException {
        return SK.getInstanceAESWithCFB(IV16(), KEY(128));
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/OFB/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOFB(byte[] iv) throws CryptoException {
        return SK.getInstanceAESWithOFB(iv, KEY(128));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOFB() throws CryptoException {
        return SK.getInstanceAESWithOFB(IV16(), KEY(128));
    }

    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCTR(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CTR/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCTR(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithCTR(iv, KEY(128));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCTR() throws CryptoException {
        return SK.getInstanceAES128WithCTR(IV16(), KEY(128));
    }
    

   /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOCB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/OCB/PKCS5Padding",
                "AES",
                new IvParameterSpec(iv == null ? Crypto.DEFAULT_IV : iv),
                new SecretKeySpec(key,"AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOCB(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithOCB(iv, KEY(128));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOCB() throws CryptoException {
        return SK.getInstanceAES128WithOCB(IV16(), KEY(128));
    }
    
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES192WithCBC(byte[] iv) throws CryptoException {
        return SK.getInstanceAESWithCBC(iv, KEY(192));
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES192WithCBC() throws CryptoException {
        return SK.getInstanceAESWithCBC(IV16(), KEY(192));
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
    
    static private byte[] KEY(int size){
        byte[] key = new byte[size / 8];
        sr.nextBytes(key);
        return key;
    }
}