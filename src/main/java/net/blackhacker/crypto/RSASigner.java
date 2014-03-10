package net.blackhacker.crypto;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

/**
 *
 * @author ben
 */

public class RSASigner {
    
    final private RSA rsa;
    final private MD md;
    
    /**
     *
     * @param publicKeyAlgorithm
     * @param digestAlgorithm
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     */
    static public RSASigner newInstance(String digestAlgorithm)  {
        
        try {
            return new RSASigner(new RSA(), new MD(digestAlgorithm));
        } catch (Exception e) {
            Logger.getLogger(RSASigner.class.getName()).log(Level.SEVERE, null, e);
        }
        
        return null;
    }
    
    private RSASigner(RSA rsa, MD md) {
        this.rsa = rsa;
        this.md = md;
    }
    
    public byte[] sign(byte[] data) {
        try {
            byte[] digest = md.digest(data);
            return rsa.encrypt(digest,rsa.getPrivateKey());
        } catch(Exception e) {
            Logger.getLogger(RSASigner.class.getName()).log(Level.SEVERE, null, e);
        }
        return null;
    }
    
    public byte[] sign(byte[] data, RSAPrivateKey key) {
        try {
            byte[] digest = md.digest(data);
            return rsa.encrypt(digest,key);
        } catch(Exception e) {
            Logger.getLogger(RSASigner.class.getName()).log(Level.SEVERE, null, e);
        }
        return null;
    }
    
    public boolean verify(byte[] data, byte[] signature) {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,rsa.getPublicKey());
            return Arrays.equals(d, c);
        } catch(Exception e) {
            Logger.getLogger(RSASigner.class.getName()).log(Level.SEVERE, null, e);
        }
        return false;
    }

    public boolean verify(byte[] data, byte[] signature, RSAPublicKey key) {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,key);
            return Arrays.equals(d, c);
        } catch(Exception e) {
            Logger.getLogger(RSASigner.class.getName()).log(Level.SEVERE, null, e);
        }
        return false;
    }
    
    /*
    public byte[] issueCertificate(PublicKey publicKey, String subject, PrivateKey privateKey){
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] subjectBytes = subject.getBytes();
        byte[] x = ArrayUtils.addAll(publicKeyEncoded, subjectBytes);
        return sign(x,privateKey);
    }
    
    public boolean verifyCertificate(byte[] certificate, PublicKey subjectPublicKey, String subject, PublicKey issuerPublicKey){
        byte[] publicKeyEncoded = subjectPublicKey.getEncoded();
        byte[] subjectBytes = subject.getBytes();
        byte[] x = ArrayUtils.addAll(publicKeyEncoded, subjectBytes);
        return verify(x,certificate,issuerPublicKey);
    }
    */
}
