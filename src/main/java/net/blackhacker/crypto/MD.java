package net.blackhacker.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author ben
 */

public class MD {
    final private MessageDigest messageDigest;
    
    private MD(String algorithm) throws CryptoException {
    	try {
            messageDigest = MessageDigest.getInstance(algorithm);
    	} catch(NoSuchAlgorithmException e) {
            throw new CryptoException(e);
    	}
    }

    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public MD getInstanceSHA256() throws CryptoException {
        return new MD("SHA-256");
    }
    
    /**
     *
     * @return
     * @throws CryptoException
     */
    final static public MD getInstanceMD5() throws CryptoException {
        return new MD("MD5");
    }
    
    
    public String getAlgorithm() {
        return messageDigest.getAlgorithm();
    }
    
    public byte[] digest(byte[] data) {
        synchronized(messageDigest) {
            byte[] digest =  messageDigest.digest(data);
            messageDigest.reset();        	
            return digest;
        }
    }
}
