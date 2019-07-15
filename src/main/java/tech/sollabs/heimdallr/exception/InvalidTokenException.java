package tech.sollabs.heimdallr.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * subclass of AuthenticationException when Token Verification failed
 *
 * @author Cyan Raphael Yi
 * @since 0.3.0
 */
public class InvalidTokenException extends AuthenticationException {

    public InvalidTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    public InvalidTokenException(String msg) {
        super(msg);
    }
}
