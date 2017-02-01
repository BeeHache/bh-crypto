/*
 * The MIT License
 *
 * Copyright 2017 ben.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package net.blackhacker.crypto.algorithm;

import java.lang.reflect.InvocationTargetException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import net.blackhacker.crypto.CryptoException;

/**
 *
 * @author ben
 */
public enum AsymetricAlgorithm {
    /* Cipher*/
    RSA(128, RSAPublicKeySpec.class, RSAPrivateKeySpec.class, null);

    AsymetricAlgorithm(
            Class <? extends KeySpec> publicKeySpecClass,
            Class <? extends KeySpec> privateKeySpecClass,
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass) {
        this(64, publicKeySpecClass, privateKeySpecClass, algorParamSpecClass);
    }   
    
    AsymetricAlgorithm(int s, 
            Class <? extends KeySpec> publicKeySpecClass,
            Class <? extends KeySpec> privateKeySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass){
        this.blockSize = s;
        this.publicKeySpecClass = publicKeySpecClass;
        this.privateKeySpecClass = privateKeySpecClass;
        this.algorParamSpecClass = algorParamSpecClass;
    }

    public int blockSize() {
        return blockSize;
    }

    public KeySpec makePublicKeySpec(final byte[] key) throws CryptoException {
        try {
            return publicKeySpecClass
                        .getConstructor(byte[].class)
                        .newInstance(key);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make keyspec", ex);
        }
    }    
    

    public KeySpec makeKeySpec(final byte[] key) throws CryptoException {
        try {
            return privateKeySpecClass
                .getConstructor(byte[].class)
                .newInstance(key);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make keyspec", ex);
        }
    }

    public AlgorithmParameterSpec makeParameterSpec(byte[] iv) throws CryptoException {
        try {
            return algorParamSpecClass
                    .getConstructor(byte[].class)
                    .newInstance(iv);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make parameter spec", ex);
        }
    }

    public AlgorithmParameterSpec makeParameterSpec(byte[] salt, int count) throws CryptoException {
        try {
            return algorParamSpecClass.getConstructor(byte[].class, int.class).newInstance(salt, count);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make parameter spec: " + ex.getLocalizedMessage(), ex);
        }
    }

    final int blockSize;
    final Class <? extends KeySpec> publicKeySpecClass;
    final Class <? extends KeySpec> privateKeySpecClass;
    final Class <? extends AlgorithmParameterSpec> algorParamSpecClass;
}
