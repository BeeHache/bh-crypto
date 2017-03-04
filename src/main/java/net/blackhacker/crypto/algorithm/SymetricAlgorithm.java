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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.blackhacker.crypto.CryptoException;
import net.blackhacker.crypto.Strings;
import net.blackhacker.crypto.Validator;

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
    
    static private Class<?>[] getClasses(Object[] objs) {
        List<Class<?>> classes = new ArrayList<>();
        for(Object obj : objs) {
            classes.add(obj.getClass());
        }
        
        return classes.toArray(new Class<?>[0]);
    }
    
    
    public KeySpec makeKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        
        try {
            try {
                return keySpecClass
                        .getConstructor(getClasses(parameters))
                        .newInstance(parameters);
                
            } catch(NoSuchMethodException e) {
                return keySpecClass
                        .getConstructor(byte[].class, String.class)
                        .newInstance(parameters[0], name());
            }
        } catch (SecurityException | InstantiationException | 
                IllegalArgumentException | IllegalAccessException | 
                InvocationTargetException | NoSuchMethodException ex) {
            throw new CryptoException(
                    String.format(Strings.COULDNT_CREATE_KEY_SPEC,
                    name(),
                    ex.getLocalizedMessage()), 
                ex);
        }
    }
    
    
    public AlgorithmParameterSpec makeParameterSpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        try {
            return algorParamSpecClass
                .getConstructor(getClasses(parameters))
                .newInstance(parameters);
        } catch (NoSuchMethodException | SecurityException | 
                InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException ex) {
            throw new CryptoException("Couldn't make parameter spec", ex);
        }
    }

    public Class<? extends KeySpec> getKeySpecClass() {
        return keySpecClass;
    }

    public Class<? extends AlgorithmParameterSpec> getAlgorParamSpecClass() {
        return algorParamSpecClass;
    }

    final int blockSize;
    int keySize;
    final String PBEName;
    final Class <? extends KeySpec> keySpecClass;
    final Class <? extends AlgorithmParameterSpec> algorParamSpecClass;
}
