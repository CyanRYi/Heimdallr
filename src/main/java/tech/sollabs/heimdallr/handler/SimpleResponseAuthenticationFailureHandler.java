package tech.sollabs.heimdallr.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler for return simple response when fail authentication process
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 * @see AuthenticationFailureHandler
 * @see ResponseAuthenticationFailureHandler
 */
public class SimpleResponseAuthenticationFailureHandler extends ResponseAuthenticationFailureHandler
        implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        handle(request, response, exception);
    }
}
