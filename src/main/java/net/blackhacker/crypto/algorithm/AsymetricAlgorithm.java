/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2017 Benjamin King aka Blackhacker(bh@blackhacker.net)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package net.blackhacker.crypto.algorithm;

import java.lang.reflect.InvocationTargetException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import net.blackhacker.crypto.CryptoException;
import net.blackhacker.crypto.Strings;
import net.blackhacker.crypto.Validator;

/**
 * Represents each of the supported asymetric algorithms
 * 
 * @author ben
 */
public enum AsymetricAlgorithm {
    /* Cipher*/
    RSA1024(1024, 936, RSAPublicKeySpec.class, RSAPrivateKeySpec.class, "RSA"),
    RSA2048(2048, 1712, RSAPublicKeySpec.class, RSAPrivateKeySpec.class, "RSA"),
    //DiffieHellman(1024, 0, DHPublicKeySpec.class, DHPrivateKeySpec.class, "DH"),
    //DSA(1024, 0, DSAPublicKeySpec.class, DSAPrivateKeySpec.class, null),
    //EC(1024, 0, ECPublicKeySpec.class, ECPrivateKeySpec.class, null),
    ;
    
    AsymetricAlgorithm(
            int keySize, 
            int blockSize,
            Class <? extends KeySpec> publicKeySpecClass,
            Class <? extends KeySpec> privateKeySpecClass,
            String name){
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.publicKeySpecClass = publicKeySpecClass;
        this.privateKeySpecClass = privateKeySpecClass;
        this.name = name;
    }
    
    public int getKeySize() {
        return keySize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public KeySpec makePublicKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        
        try {
            try{
                return publicKeySpecClass
                    .getConstructor(getClasses(parameters))
                    .newInstance(parameters);
            } catch (NoSuchMethodException e){
            }

            try{
                return X509EncodedKeySpec.class
                    .getConstructor(getClasses(parameters))
                    .newInstance(parameters);
            } catch (NoSuchMethodException e) {
            }
            
            throw new CryptoException("Unsupported parameters");
            
        } catch (SecurityException | InstantiationException | 
                IllegalArgumentException | IllegalAccessException | 
                InvocationTargetException ex) {
            throw new CryptoException(
                String.format(Strings.COULDNT_CREATE_KEY_SPEC_MSG_FMT,
                    name(),
                    ex.getLocalizedMessage()), 
                ex);
        }
    }
    

    public KeySpec makePrivateKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        
        try {
            try {
            return privateKeySpecClass
                .getConstructor(getClasses(parameters))
                .newInstance(parameters);
            } catch(NoSuchMethodException e){
            }
            
            try {
            return PKCS8EncodedKeySpec.class
                .getConstructor(getClasses(parameters))
                .newInstance(parameters);
            } catch(NoSuchMethodException e) {
            }
            
            throw new CryptoException("Unsupported parameters");
            
        } catch (SecurityException | InstantiationException | 
                IllegalAccessException | IllegalArgumentException | 
                InvocationTargetException ex) {
            throw new CryptoException(
                    String.format(Strings.COULDNT_CREATE_KEY_SPEC_MSG_FMT,
                        name(),
                        ex.getLocalizedMessage()), 
                    ex);
        }
    }
    
    static private Class<?>[] getClasses(Object[] objs) {
        List<Class<?>> classes = new ArrayList<>();
        for(Object obj : objs) {
            classes.add(obj.getClass());
        }
        
        return classes.toArray(new Class<?>[0]);
    }
    
    
    @Override
    public String toString() {
        return name == null ? name() : name;
    }

    public Class<? extends KeySpec> getPublicKeySpecClass() {
        return publicKeySpecClass;
    }

    public Class<? extends KeySpec> getPrivateKeySpecClass() {
        return privateKeySpecClass;
    }

    final int keySize;
    int blockSize;
    final String name;
    final Class <? extends KeySpec> publicKeySpecClass;
    final Class <? extends KeySpec> privateKeySpecClass;
}
