package net.blackhacker.crypto;

import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author ben
 */
public class PBE extends SKBase {
	static private int ITERATION = 5000;
    final private byte salt[];
    
    public PBE(String algorithm, byte[] salt) throws CryptoException {
        super(algorithm);
        this.salt = salt;
    }

    public PBE(String algorithm, String passphrase, byte[] salt) throws CryptoException {
        super(algorithm);
        this.salt = salt;
        generateSecretKey(passphrase);
    }    
    
    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        return encrypt(data,getSecretKey(), new PBEParameterSpec(salt, ITERATION));
    }

    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        return decrypt(data,getSecretKey(), new PBEParameterSpec(salt, ITERATION));
    }
}
