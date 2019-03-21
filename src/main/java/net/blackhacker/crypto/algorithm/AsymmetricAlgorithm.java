/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2019 Benjamin King aka Blackhacker(bh@blackhacker.net)
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
import java.security.spec.X509EncodedKeySpec;
import net.blackhacker.crypto.CryptoException;
import net.blackhacker.crypto.Strings;
import net.blackhacker.crypto.utils.Utils;
import net.blackhacker.crypto.utils.Validator;

/**
 * Represents each of the supported asymmetric algorithms
 * 
 * @author Benjamin King aka Blackhacker(bh@blackhacker.net)
 */
public enum AsymmetricAlgorithm {
    /* Cipher*/
    RSA1024(1024, 936, "RSA"),
    RSA2048(2048, 1712, "RSA"),
    //DiffieHellman(1024, 0, DHPublicKeySpec.class, DHPrivateKeySpec.class, "DH"),
    DSA1024(1024, 64, "DSA"),
    DSA2048(2048, 64, "DSA"),
    DSA3072(3072, 64, "DSA")
    //EC(1024, 0, ECPublicKeySpec.class, ECPrivateKeySpec.class, null),
    ;
    
    AsymmetricAlgorithm(int keySize, int blockSize,String name) {
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.name = name;
    }
    
    /**
     * The size of key in bits
     * 
     * @return The size of keys in bits
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Size of block in bits
     * 
     * @return size of block in bits
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Builds a KeySpec for a PubliceKey based THIS and the parameters given
     * 
     * @param parameters
     * @return KeySpec
     * @throws CryptoException
     */
    public KeySpec makePublicKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "Must give parameters");
        try {
            Class<?>[] classes = Utils.getClasses(parameters);

            try {
                
                return parameters.length == 0 
                        ? X509EncodedKeySpec.class.newInstance()
                        : X509EncodedKeySpec.class
                            .getConstructor(classes)
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
    
    /**
     * Builds a KeySpec for a PrivateKey based THIS and the parameters given
     * 
     * @param parameters
     * @return PrivateKeySpec
     * @throws CryptoException
     */
    public KeySpec makePrivateKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        
        try {
            Class<?>[] classes = Utils.getClasses(parameters);
            
            try {
                return PKCS8EncodedKeySpec.class
                    .getConstructor(classes)
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
    
    /**
     *
     * @return
     */
    @Override
    public String toString() {
        return name;
    }

    final int keySize;
    int blockSize;
    final String name;
}
