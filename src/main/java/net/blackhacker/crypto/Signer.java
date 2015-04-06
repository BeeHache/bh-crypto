package net.blackhacker.crypto;

import java.util.Arrays;

/**
 *
 * @author ben
 */
public class Signer {
    final private Encryptor crypto;
    final private MD md;
    
    private Signer(Encryptor crypto, MD md) {
        this.crypto = crypto;
        this.md = md;
    }

    /**
     *
     * @return Signer Object
     * @throws net.blackhacker.crypto.SignerException
     */
    static public Signer newInstanceDESwithMD5() throws SignerException {
        try {
            return new Signer(SK.getInstanceDESWithECB(), MD.getInstanceMD5());
        } catch(CryptoException e) {
            throw new SignerException("Coun't init DES Signer",e);
        }
    }

    /**
     *
     * @param passphrase
     * @param cipherAlgorithm
     * @param keyAlgorithm
     * @param digestAlgorithm
     * @return
     * @throws net.blackhacker.crypto.SignerException
     *
    static public Signer newInstancePBE(String passphrase, String cipherAlgorithm, String keyAlgorithm, String digestAlgorithm) 
            throws SignerException {
        try {
            return new Signer(new PBE(cipherAlgorithm, keyAlgorithm, passphrase), new MD(digestAlgorithm));
        } catch (CryptoException e) {
            throw new SignerException("Coun't init PBE Signer",e);
        }
    }
    */ 
    
    /**
     *
     * @return Signer object
     * @throws net.blackhacker.crypto.SignerException
     */
    static public Signer newInstanceRSAWithMD5() throws SignerException  {
        
        try {
            return new Signer(new RSA(), MD.getInstanceMD5());
        } catch (CryptoException e) {
            throw new SignerException("Coun't init RSA Signer",e);
        }
    }    
    
    /**
     * signs an array of bytes
     * @param data
     * @return signature for given data
     * @throws net.blackhacker.crypto.SignerException
     */
    public byte[] sign(byte[] data) throws SignerException {
        try {
            byte[] digest = md.digest(data);
            return crypto.encrypt(digest);
        } catch (Exception ex) {
            throw new SignerException("Couldn't sign data",ex);
        }
    }
    
    /**
     * verifies signature for a given array of bytes
     * @param data
     * @param signature
     * @return true 
     * @throws net.blackhacker.crypto.SignerException 
     */
    public boolean verify(byte[] data, byte[] signature) throws SignerException {
        try {
            byte[] d = md.digest(data);
            byte[] c = crypto.decrypt(signature);
            return Arrays.equals(d, c);
        } catch(CryptoException ex) {
            return false;
        } catch (Exception ex) {
            throw new SignerException("Couldn't verify signature",ex);
        }
    }
}
