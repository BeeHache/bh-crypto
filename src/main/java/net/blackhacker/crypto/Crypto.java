package net.blackhacker.crypto;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ben
 */
public class Crypto {
    final private Cipher cipher;
    final private SecureRandom secureRandom;
    
    static final Logger LOG = Logger.getLogger(Crypto.class.getName());
    
    public  Crypto(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        cipher = Cipher.getInstance(algorithm);
        secureRandom = new SecureRandom();
    }
   
    public byte[] encrypt(byte[] data, Key key) {
        return encrypt(data,key, null);
    }
    
    public byte[] encrypt(byte[] data, Key key, AlgorithmParameterSpec param) {
        synchronized(cipher) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, key, param);
                return cipher.doFinal(data);
            } catch (Exception ex) {
                LOG.log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    public byte[] decrypt(byte[] data, Key key) {
        return decrypt(data, key, null);
    }
    
    public byte[] decrypt(byte[] data, Key key, AlgorithmParameterSpec param) {
        if (data==null) {
            return null;
        }
        
        synchronized(cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, param);
                return cipher.doFinal(data);
            } catch (Exception ex) {
                LOG.log(Level.SEVERE, null, ex);
            }
            return null;
        }
    }
   
    public Cipher getCipher()  {
        return cipher;
    }
   
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }
    
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }
}