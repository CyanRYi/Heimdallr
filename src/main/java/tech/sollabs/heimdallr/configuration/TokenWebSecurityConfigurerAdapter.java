package tech.sollabs.heimdallr.configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

/**
 * Configurer Adapter to configure Token Authentication
 * When {@link TokenVerificationService} and {@link AuthenticationSuccessHandler} beans are not exists,
 * Exception will be thrown from {@link TokenAuthenticationConfigurer}
 *
 * @author Cyan Raphael Yi
 * @since 0.4.0
 *
 * @see TokenAuthenticationConfigurer
 */
public abstract class TokenWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    /**
     * Override this method to configure Token Security.
     * or call super configure additional Security configuration.
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);

        http.apply(new TokenAuthenticationConfigurer(tokenVerificationService())
                        .enableRefresh("/refresh")
                        .onRefreshSuccess(tokenRefreshSuccessHandler())
                        .onRefreshFailure(tokenRefreshFailureHandler()));
    }

    /**
     * Override this method to provide {@link TokenVerificationService} for Token Authentication
     */
    protected abstract TokenVerificationService tokenVerificationService();

    /**
     * Override this method to create {@link AuthenticationSuccessHandler} to return new Token when success token refresh.
     */
    protected abstract AuthenticationSuccessHandler tokenRefreshSuccessHandler();

    /**
     * Override this method to create {@link AuthenticationFailureHandler} when token refresh failed.
     */
    protected AuthenticationFailureHandler tokenRefreshFailureHandler() {
        return new SimpleResponseAuthenticationFailureHandler();
    }
}
