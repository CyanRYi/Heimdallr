package tech.sollabs.heimdallr.web.context;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public interface TokenVerificationService {

    Authentication verifyToken(String token) throws AuthenticationException;
}
