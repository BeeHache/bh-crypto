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
import javax.crypto.spec.SecretKeySpec;

/**
 * Factory for class for Symmetric or SecretKey algorithms.
 * 
 * @author bh@blackhacker.net
 */
public class SK extends Encryptor {
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
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException("Couldn't create key factory: " + ex.getLocalizedMessage(),ex);
        }
    }
    
    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : ECB
     * 
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithECB() throws CryptoException {
        return new SK("DES/ECB/PKCS5Padding", "DES", null);
    }

    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : ECB
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
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @param iv initialization vector
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCBC(byte[] iv) throws CryptoException {
        return new SK("DES/CBC/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCBC(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/CBC/PKCS5Padding","DES",IV64_BIT_CHECK(iv),new DESKeySpec(key)
            );
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Factory method initialized with :
     * 
     * Algorithm : DES
     * Mode : CBC
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCBC() throws CryptoException {
        return SK.getInstanceDESWithCBC(RANDOM_64_BITS());
    }

    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCFB(byte[] iv) throws CryptoException {
        return new SK("DES/CFB/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/CFB/PKCS5Padding","DES", IV64_BIT_CHECK(iv), new DESKeySpec(key)
            );
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Algorithm : DES
     * Mode : CFB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithCFB() throws CryptoException {
        return SK.getInstanceDESWithCFB(RANDOM_64_BITS());
    }    

    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithOFB(byte[] iv) throws CryptoException {
        return new SK("DES/OFB/PKCS5Padding", "DES", IV64_BIT_CHECK(iv));
    }

    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithOFB(byte[] iv, byte[] key) throws CryptoException {
        try {
            return new SK("DES/OFB/PKCS5Padding","DES", IV64_BIT_CHECK(iv), new DESKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }
    
    /**
     * Algorithm : DES
     * Mode : OFB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESWithOFB() throws CryptoException {
        return SK.getInstanceDESWithOFB(RANDOM_64_BITS());
    }
    
    
    /**
     * Algorithm : Triple DES
     * Mode : ECB
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithECB() throws CryptoException {
        return new SK("DESede/ECB/PKCS5Padding", "DESede", null);
    }

    /**
     * Algorithm : Triple DES
     * Mode : ECB
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithECB(byte[] key) throws CryptoException {
        try {
            return new SK("DESede/ECB/PKCS5Padding", "DESede", null, new DESedeKeySpec(key));
        } catch (InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }    
    
    /**
     * Algorithm : Triple DES
     * Mode : CBC
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithCBC(byte[] iv) throws CryptoException {
        return new SK("DESede/CBC/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv));
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
            return new SK("DESede/CBC/PKCS5Padding","DESede", IV64_BIT_CHECK(iv), new DESedeKeySpec(key));
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
        return SK.getInstanceDESedeWithCBC(RANDOM_64_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithCFB(byte[] iv) throws CryptoException {
        return new SK("DESede/CFB/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv)
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
            return new SK("DESede/CFB/PKCS5Padding","DESede", IV64_BIT_CHECK(iv), new DESedeKeySpec(key));
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
        return SK.getInstanceDESedeWithCFB(RANDOM_64_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceDESedeWithOFB(byte[] iv) throws CryptoException {
        return new SK("DESede/OFB/PKCS5Padding", "DESede", IV64_BIT_CHECK(iv));
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
                    IV64_BIT_CHECK(iv),
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
        return SK.getInstanceDESedeWithOFB(RANDOM_64_BITS());
    }
    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithECB(byte[] key) throws CryptoException {
        return new SK(
                "AES/ECB/PKCS5Padding",
                "AES",
                null,
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithECB() throws CryptoException {
        return SK.getInstanceAES128WithECB(RANDOM_BITS(128));
    }
    
    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CBC/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCBC(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithCBC(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCBC() throws CryptoException {
        return SK.getInstanceAES128WithCBC(RANDOM_128_BITS(), RANDOM_128_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCFB(final byte[] iv, final byte[] key) 
            throws CryptoException {
        return new SK(
                "AES/CFB/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCFB(final byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithCFB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCFB() throws CryptoException {
        return SK.getInstanceAES128WithCFB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOFB(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/OFB/PKCS5Padding",
                "AES",
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOFB(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithOFB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOFB() throws CryptoException {
        return SK.getInstanceAES128WithOFB(DEFAULT_IV128, RANDOM_128_BITS());
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
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCTR(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithCTR(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithCTR() throws CryptoException {
        return getInstanceAES128WithCTR(DEFAULT_IV128, RANDOM_128_BITS());
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
                IV128_BIT_CHECK(iv),
                KEY128_BIT_CHECK(key, "AES")
        );
    }

    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOCB(byte[] iv) throws CryptoException {
        return SK.getInstanceAES128WithOCB(iv, RANDOM_128_BITS());
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES128WithOCB() throws CryptoException {
        return SK.getInstanceAES128WithOCB(DEFAULT_IV128, RANDOM_128_BITS());
    }

    /**
     *
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES192WithECB(byte[] key) throws CryptoException {
        return new SK("AES/ECB/PKCS5Padding","AES",null,KEY192_BIT_CHECK(key, "AES"));
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES192WithECB() throws CryptoException {
        return SK.getInstanceAES192WithECB(RANDOM_192_BITS());
    }
    
    /**
     *
     * @param iv
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceARANDOM_BITS92WithCBC(byte[] iv) throws CryptoException {
        return SK.getInstanceAES192WithCBC(iv, RANDOM_192_BITS());
    }

    /**
     *
     * @param iv
     * @param key
     * @return
     * @throws CryptoException
     */
    final static public SK getInstanceAES192WithCBC(byte[] iv, byte[] key) throws CryptoException {
        return new SK(
                "AES/CBC/PKCS5Padding",
                "AES",
                IV192_BIT_CHECK(iv),
                KEY192_BIT_CHECK(key, "AES")
        );
    }    
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public SK getInstancRANDOM_BITSS192WithCBC() throws CryptoException {
        return SK.getInstanceAES192WithCBC(DEFAULT_IV128, RANDOM_192_BITS());
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
        SecureRandom secureRandom = getSecureRandom();
        
        synchronized(this) {
            try {
                if (param !=null) {
                    cipher.init(Cipher.ENCRYPT_MODE, key, param, secureRandom);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
                }
                
                return cipher.doFinal(data);
            } catch (Exception ex) {
            	throw new CryptoException("Could not encrypt data!", ex);
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
            	throw new CryptoException("Could not decrypt data: " + ex.getLocalizedMessage(),ex);
            }
        }
    }
    
    /**
     * 
     * @return
     * @throws CryptoException 
     */
    public Key getKey() throws CryptoException {
        return key;
    }
    
    /**
     * 
     * @return Key in bytes
     */
    public byte[] getKeyEncoded() {
        return key.getEncoded();
    }
}