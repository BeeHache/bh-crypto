package net.blackhacker.crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.blackhacker.utils.ByteArrayList;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author ben
 */

public class RSASigner {
    
    final private RSA rsa;
    final private MD md;
    
    final private Gson gson = new GsonBuilder()
                    .setPrettyPrinting()
                    .registerTypeAdapter(
                        byte[].class,
                        new ByteArrayToBase64TypeAdapter())
                    .create();
    
    static final Logger LOG = Logger.getLogger(RSASigner.class.getName());
    
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
    
    /**
     *
     * @param digestAlgorithm
     * @return
     */
    static public RSASigner newInstance(String digestAlgorithm)  {
        
        try {
            return new RSASigner(new RSA(), new MD(digestAlgorithm));
        } catch (Exception e) {
            LOG.log(Level.SEVERE, null, e);
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
            LOG.log(Level.SEVERE, null, e);
        }
        return null;
    }
    
    public byte[] sign(byte[] data, RSAPrivateKey key) {
        try {
            byte[] digest = md.digest(data);
            return rsa.encrypt(digest,key);
        } catch(Exception e) {
            LOG.log(Level.SEVERE, null, e);
        }
        return null;
    }
    
    public boolean verify(byte[] data, byte[] signature) {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,rsa.getPublicKey());
            return Arrays.equals(d, c);
        } catch(Exception e) {
            LOG.log(Level.SEVERE, null, e);
        }
        return false;
    }

    public boolean verify(byte[] data, byte[] signature, RSAPublicKey key) {
        try {
            byte[] d = md.digest(data);
            byte[] c = rsa.decrypt(signature,key);
            return Arrays.equals(d, c);
        } catch(Exception e) {
            LOG.log(Level.SEVERE, null, e);
        }
        return false;
    }
    
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
    
    public byte[] issueCertificate(PublicKey publicKey, String subject, String signer) {
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
    
    public PublicKey extractPublicKey(byte[]signedCert) {
        PublicKey publicKey = null;
        try {
            ByteArrayList bal = ByteArrayList.fromByteArray(signedCert);
            if (bal.size()==2) {
                byte[] cert = bal.get(0);
                byte[] sig = bal.get(1);

                bal = ByteArrayList.fromByteArray(cert);
                if (bal.size()==3) {
                    byte[] key = bal.get(0);
                    publicKey =  KeyFactory
                    .getInstance(rsa.getAlgorithm())
                    .generatePublic(new X509EncodedKeySpec(key));
                }
            }
        } finally {
            return publicKey;
        }
    }
    
    public boolean verifyCertificate(byte[] signedCert, RSAPublicKey signerKey) {
        ByteArrayList bal = ByteArrayList.fromByteArray(signedCert);
        
        if (bal.size()==2) {
            byte[] cert = bal.get(0);
            byte[] sig = bal.get(1);
        
            return verify(cert,sig,signerKey);
        }
        return false;
    }
}
