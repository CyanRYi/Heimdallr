package tech.sollabs.heimdallr.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler for return simple response when success authentication process
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 * @see AuthenticationSuccessHandler
 * @see ResponseAuthenticationSuccessHandler
 */
public class SimpleResponseAuthenticationSuccessHandler extends ResponseAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        handle(request, response, authentication);
    }
}
