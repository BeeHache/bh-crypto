package net.blackhacker.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.blackhacker.utils.ByteArrayList;

/**
 *
 * @author ben
 */

public class RSASigner {
    
    final private RSA rsa;
    final private MD md;

    /*
    public class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

        @Override
        public byte[] deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
            return Base64.encodeBase64(
                jsonElement.getAsString().getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public JsonElement serialize(byte[] bytes, Type type, JsonSerializationContext jsonSerializationContext) {
            return new JsonPrimitive(Base64.encodeBase64String(bytes));
        }
    }
    */
    
    /**
     *
     * @param digestAlgorithm
     * @return
     */
    static public RSASigner newInstance(String digestAlgorithm) throws SignerException  {
        
        try {
            return new RSASigner(new RSA(), new MD(digestAlgorithm));
        } catch (CryptoException e) {
            throw new SignerException("",e);
        }
    }
    
    private RSASigner(RSA rsa, MD md) {
        this.rsa = rsa;
        this.md = md;
    }
    
    public byte[] sign(byte[] data) throws SignerException {
        try {
            byte[] digest = md.digest(data);
            return rsa.encrypt(digest,rsa.getPrivateKey());
        } catch(CryptoException e) {
            throw new SignerException("",e);
        }
    }
    
    public byte[] sign(byte[] data, RSAPrivateKey key) throws SignerException {
        try {
            byte[] digest = md.digest(data);
            return rsa.encrypt(digest,key);
        } catch(CryptoException e) {
            throw new SignerException("",e);
        }
    }
    
    public boolean verify(byte[] data, byte[] signature) throws SignerException {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,rsa.getPublicKey());
            return Arrays.equals(d, c);
        } catch(CryptoException e) {
            throw new SignerException("",e);
        }
    }

    public boolean verify(byte[] data, byte[] signature, RSAPublicKey key) throws SignerException {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,key);
            return Arrays.equals(d, c);
        } catch(CryptoException e) {
            throw new SignerException("",e);
        }
    }
    
    /*
    public PublicKey getPublicKey(byte[] certificate) {
       ByteArrayInputStream bais = new ByteArrayInputStream(certificate);
       DataInputStream dis = new DataInputStream(bais);
       PublicKey publicKey = null;
       try {
           int keyPos = dis.readInt();
           int keyLen = dis.readInt();
           
           byte[] key = Arrays.copyOfRange(certificate, keyPos, keyPos + keyLen);
           
           publicKey = KeyFactory
                .getInstance(rsa.getAlgorithm())
                .generatePublic(new X509EncodedKeySpec(key));
           
       } catch(Exception ex) {
           throw new RuntimeException("Could't read certificate", ex);
       }
       
       return publicKey;
    }
    */
    
    public byte[] issueCertificate(PublicKey publicKey, String subject, String signer) throws SignerException {
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] subjectBytes = subject.getBytes(StandardCharsets.UTF_8);
        byte[] signerBytes = signer.getBytes(StandardCharsets.UTF_8);

        ByteArrayList bal = new ByteArrayList();
        bal.add(publicKeyEncoded);
        bal.add(subjectBytes);
        bal.add(signerBytes);
        byte[] cert = bal.toByteArray();

        byte[] sig = sign(cert);

        ByteArrayList bal2 = new ByteArrayList();
        bal2.add(cert);
        bal2.add(sig);

        return bal2.toByteArray();

    }
    
    public PublicKey extractPublicKey(byte[]signedCert) throws SignerException  {
        PublicKey publicKey = null;
        try {
            ByteArrayList bal = ByteArrayList.fromByteArray(signedCert);
            if (bal.size() != 2) {
                throw new SignerException("Can't extract cert");
            }
            
            byte[] cert = bal.get(0);

            bal = ByteArrayList.fromByteArray(cert);
            if (bal.size() != 3) {
                throw new SignerException("Can't extract key");
            }
            
            byte[] key = bal.get(0);
            publicKey =  KeyFactory
                .getInstance(rsa.getAlgorithm())
                .generatePublic(new X509EncodedKeySpec(key));
            
        } catch (NoSuchAlgorithmException e) {
            throw new SignerException("Can't extract key",e);
        } catch (InvalidKeySpecException e) {
            throw new SignerException("Can't extract key",e);
        }
        return publicKey;
    }
    
    public boolean verifyCertificate(byte[] signedCert, RSAPublicKey signerKey) throws SignerException {
        ByteArrayList bal = ByteArrayList.fromByteArray(signedCert);
        
        if (bal.size()==2) {
            byte[] cert = bal.get(0);
            byte[] sig = bal.get(1);
        
            return verify(cert,sig,signerKey);
        }
        return false;
    }
}
