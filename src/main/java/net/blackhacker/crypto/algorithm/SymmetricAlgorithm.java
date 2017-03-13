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
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import net.blackhacker.crypto.CryptoException;
import net.blackhacker.crypto.Strings;
import net.blackhacker.crypto.Utils;
import net.blackhacker.crypto.Validator;

/**
 * Represents each of the supported symetric algorithms
 * 
 * @author ben
 */
public enum SymmetricAlgorithm {
    AES(128, SecretKeySpec.class, IvParameterSpec.class),
    AES192(192, SecretKeySpec.class, IvParameterSpec.class, "AES"),
    AES256(256, SecretKeySpec.class, IvParameterSpec.class, "AES"),
    //AESWrap(128, null, null),
    //ARCFOUR, 
    //Blowfish,
    //CCM,
    DES(DESKeySpec.class, IvParameterSpec.class), 
    DESede(64, DESedeKeySpec.class, IvParameterSpec.class, "TripleDES"),
    //DESedeWrap,
    //ECIES,
    //GCM, 
    //RC2, 
    //RC4, 
    //RC5
    ;

    SymmetricAlgorithm(
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass) {
        this(64, keySpecClass, algorParamSpecClass, null);
    }

    SymmetricAlgorithm(int s,
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass) {
        this(s, keySpecClass, algorParamSpecClass, null);
    }
    
    SymmetricAlgorithm(
            int s, 
            Class <? extends KeySpec> keySpecClass, 
            Class <? extends AlgorithmParameterSpec> algorParamSpecClass,
            String PBEName ){
        this.blockSize = s;
        this.keySpecClass = keySpecClass;
        this.algorParamSpecClass = algorParamSpecClass;
        this.PBEName = PBEName;
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
     * PBE Name
     * @return PBE Name
     */
    public String getPBEName() {
        return PBEName == null ? name() : PBEName;
    }
    
    /**
     * Creates new KeySpec based on internal keySpecClass and the given
     * parameters
     * 
     * @param parameters
     * @return KeySpec
     * @throws CryptoException
     * @see KeySpec
     */
    public KeySpec makeKeySpec(Object... parameters) throws CryptoException {
        Validator.isTrue(parameters.length > 0, "parameters are empty");
        Class<?>[] classes = Utils.getClasses(parameters);
        try {
            try {
                return keySpecClass
                    .getConstructor(classes)
                    .newInstance(parameters);
            } catch (NoSuchMethodException ex) {
            }
            
            try {
                return keySpecClass
                    .getConstructor(parameters[0].getClass(), String.class)
                    .newInstance(parameters[0], name());
            } catch (NoSuchMethodException ex) {
            }
            
            try {
                return PBEKeySpec.class
                    .getConstructor(classes)
                    .newInstance(parameters);
            } catch (NoSuchMethodException ex) {
            }
            
            throw new CryptoException("Unsupported parameters");
            
        }  catch (SecurityException | InstantiationException | 
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
     * Instantiates new AlgorithmParameterSpec from internal AlgorithmParameterSpec
     * class object and the given parameters
     * 
     * @param parameters
     * @return AlgorithmParameterSpec
     * @throws CryptoException
     * @see AlgorithmParameterSpec
     */
    public AlgorithmParameterSpec makeParameterSpec(Object... parameters) 
            throws CryptoException {
        Validator.isTrue(parameters.length > 0, "");
        try {
            return algorParamSpecClass
                .getConstructor(Utils.getClasses(parameters))
                .newInstance(parameters);
        } catch (NoSuchMethodException ex) {
            throw new CryptoException("Unsupported parameters");
            
        } catch (SecurityException | InstantiationException | 
                IllegalAccessException | IllegalArgumentException | 
                InvocationTargetException ex) {
            throw new CryptoException("Couldn't make parameter spec", ex);
        }
    }

    public Class<? extends KeySpec> getKeySpecClass() {
        return keySpecClass;
    }

    public Class<? extends AlgorithmParameterSpec> getAlgorParamSpecClass() {
        return algorParamSpecClass;
    }

    final private int blockSize;
    final private String PBEName;
    final private Class <? extends KeySpec> keySpecClass;
    final private Class <? extends AlgorithmParameterSpec> algorParamSpecClass;
}
