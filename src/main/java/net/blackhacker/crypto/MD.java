package net.blackhacker.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author ben
 */

public class MD {
    final private MessageDigest messageDigest;
    
    public MD(String algorithm) throws CryptoException {
    	try {
            messageDigest = MessageDigest.getInstance(algorithm);
    	} catch(NoSuchAlgorithmException e) {
            throw new CryptoException(e);
    	}
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
