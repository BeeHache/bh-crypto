package net.blackhacker.crypto;

import java.security.Key;

/**
 *
 * @author ben
 */
public class UnsupportedKeyTypeException extends Exception {
    
    public UnsupportedKeyTypeException(Key key) {
        super("Key unsuppted : " + key.getClass().getName());
    }    
}
