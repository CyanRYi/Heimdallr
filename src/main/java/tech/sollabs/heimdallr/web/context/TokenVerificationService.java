package tech.sollabs.heimdallr.web.context;

import org.springframework.security.core.Authentication;
import tech.sollabs.heimdallr.exception.InvalidTokenException;

/**
 * Create Authentication from valid token
 * when Token is Invalid, throw {@link InvalidTokenException}
 */
public interface TokenVerificationService {

    Authentication verifyToken(String token) throws InvalidTokenException;
}
