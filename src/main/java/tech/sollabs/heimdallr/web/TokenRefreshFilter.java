package tech.sollabs.heimdallr.web;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Refresh Access Token.
 * When request already Authenticated,
 * issue new Token by {@link AuthenticationSuccessHandler)}
 *
 * @see tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer
 * @see tech.sollabs.heimdallr.web.TokenSecurityContextFilter
 */
public class TokenRefreshFilter extends AbstractAuthenticationProcessingFilter {

    public TokenRefreshFilter(String defaultFilterProcessesUrl, AuthenticationSuccessHandler refreshSuccessHandler) {
        super(defaultFilterProcessesUrl);
        Assert.notNull(refreshSuccessHandler, "AuthenticationSuccessHandler is required to return new Token.");
        super.setAuthenticationSuccessHandler(refreshSuccessHandler);
        super.setAuthenticationFailureHandler(new SimpleResponseAuthenticationFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadCredentialsException("Token Refreshing must be process after Authentication");
        }

        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                    authResult, this.getClass()));
        }

        getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
        SecurityContextHolder.clearContext();
    }
}