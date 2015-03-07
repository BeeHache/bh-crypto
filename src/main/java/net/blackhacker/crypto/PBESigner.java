package net.blackhacker.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author ben
 */

public class PBESigner {
    
    final private PBE pbe;
    final private MD md;
    
    /**
     *
     * @param passphrase
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param digestAlgorithm
     * @param salt
     * @param keyLength
     * @return
     * @throws net.blackhacker.crypto.CryptoException
     */
    static public PBESigner newInstance(String passphrase, String cipherAlgorithm, String keyAlgorithm, String digestAlgorithm, byte[] salt, int keyLength) 
            throws CryptoException {
        return new PBESigner(new PBE(cipherAlgorithm, keyAlgorithm, passphrase, salt), new MD(digestAlgorithm));
    }
    
    private PBESigner(PBE sk, MD md) {
        this.pbe = sk;
        this.md = md;
    }
    
    public byte[] sign(byte[] data) {
        try {
            byte[] digest = md.digest(data);
            return pbe.encrypt(digest);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public boolean verify(byte[] data, byte[] signature) {
        try {
            byte[] d = md.digest(data);
            byte[] c = pbe.decrypt(signature);
            return Arrays.equals(d, c);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /*
    public byte[] issueCertificate(PublicKey publicKey, String subject){
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] subjectBytes = subject.getBytes();
        byte[] x = ArrayUtils.addAll(publicKeyEncoded, subjectBytes);
        return sign(x,privateKey, salt);
    }
   
    public boolean verifyCertificate(byte[] certificate, PublicKey subjectPublicKey, String subject, PublicKey issuerPublicKey, byte[] salt){
        byte[] publicKeyEncoded = subjectPublicKey.getEncoded();
        byte[] subjectBytes = subject.getBytes();
        byte[] x = ArrayUtils.addAll(publicKeyEncoded, subjectBytes);
        return verify(x,certificate,issuerPublicKey, salt);
    }
    */ 

}
