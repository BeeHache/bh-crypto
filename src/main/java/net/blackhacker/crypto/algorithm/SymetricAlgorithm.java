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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.blackhacker.crypto.CryptoException;

/**
 * Represents each of the supported symetric algorithms
 * 
 * @author ben
 */
public enum SymetricAlgorithm {
    /* Cipher*/
    AES(128, SecretKeySpec.class, IvParameterSpec.class),
    AES192(192, SecretKeySpec.class, IvParameterSpec.class, "AES"),
    AES256(256, SecretKeySpec.class, IvParameterSpec.class, "AES"),
    AESWrap(128, null, null),
    ARCFOUR, 
    Blowfish,
    CCM,
    DES(DESKeySpec.class, IvParameterSpec.class), 
    DESede(64, DESedeKeySpec.class, IvParameterSpec.class, "TripleDES"),
    DESedeWrap,
    ECIES,
    GCM, 
    RC2, 
    RC4, 
    RC5;

    SymetricAlgorithm(){
        this(64, null, null, null);
    }

    SymetricAlgorithm(
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass) {
        this(64, keySpecClass, algorParamSpecClass, null);
    }

    SymetricAlgorithm(int s,
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass) {
        this(s, keySpecClass, algorParamSpecClass, null);
    }
    
    SymetricAlgorithm(
            int s, 
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass,
            String PBEName ){
        this.blockSize = s;
        this.keySpecClass = keySpecClass;
        this.algorParamSpecClass = algorParamSpecClass;
        this.PBEName = PBEName;
    }

    public int getBlockSize() {
        return blockSize;
    }
    
    public int getKeySize() {
        return keySize;
    }
    
    public String getPBEName() {
        return PBEName == null ? name() : PBEName;
    }

    public KeySpec makeKeySpec(final byte[] key) throws CryptoException {
        try {
            if (keySpecClass.equals(SecretKeySpec.class))
                return keySpecClass
                        .getConstructor(byte[].class, String.class)
                        .newInstance(key, name());
            else
                return keySpecClass
                        .getConstructor(byte[].class)
                        .newInstance(key);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make keyspec", ex);
        }
    }

    public KeySpec makeKeySpec(final char[] password) throws CryptoException {
        try {
            Constructor<? extends KeySpec> con = keySpecClass.getConstructor(char[].class);
            if (con!=null){
                return con.newInstance(password);
            }
            throw new CryptoException(name() + "Not a PBE Algorithm");
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
    int keySize;
    final String PBEName;
    final Class <? extends KeySpec> keySpecClass;
    final Class <? extends AlgorithmParameterSpec> algorParamSpecClass;
}
