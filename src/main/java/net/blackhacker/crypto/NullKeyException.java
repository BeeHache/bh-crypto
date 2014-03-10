package net.blackhacker.crypto;

/**
 *
 * @author ben
 */
public class NullKeyException extends RuntimeException {
    public NullKeyException() {
        super("Key not generated");
    }
}
