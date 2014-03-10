package net.blackhacker.crypto;

import java.security.*;

/**
 *
 * @author ben
 */

public class MD {
    final private MessageDigest messageDigest;
    
    public MD(String algorithm) throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance(algorithm);
    }
    
    public String getAlgorithm() {
        return messageDigest.getAlgorithm();
    }
    
    public byte[] digest(byte[] data) {
        synchronized(messageDigest) {
            byte[] digest=  messageDigest.digest(data);
            messageDigest.reset();
            return digest;
        }
    }
}
