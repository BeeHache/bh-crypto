/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package net.blackhacker.crypto;

/**
 *
 * @author ben
 */
public class SignerException extends Exception {

    public SignerException() {
    }

    public SignerException(String message) {
        super(message);
    }

    public SignerException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
