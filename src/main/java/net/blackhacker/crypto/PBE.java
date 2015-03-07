package net.blackhacker.crypto;

import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author ben
 */
public class PBE extends SKBase {
    static private int ITERATION = 5000;
    final private byte salt[];
    
    public PBE(String cipherAlgorithm, String keyAlgorithm, byte[] salt) throws CryptoException {
        super(cipherAlgorithm, keyAlgorithm);
        this.salt = salt;
    }

    public PBE(String cipherAlorithm, String keyAlgorithm, String passphrase, byte[] salt) throws CryptoException {
        super(cipherAlorithm,keyAlgorithm);
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

    @Override
    public KeySpec generateKeySpec(char[] passphrase) {
        return new PBEKeySpec(passphrase);
    }
}
