package tech.sollabs.heimdallr.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer;
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
public class TokenWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired(required = false)
    private TokenVerificationService tokenVerificationService;
    @Autowired(required = false)
    private AuthenticationSuccessHandler tokenRefreshSuccessHandler;

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
                        .onRefreshSuccess(tokenRefreshSuccessHandler()));
    }

    /**
     * Provide {@link TokenVerificationService} Spring bean autowired
     * or override this method to create new object
     */
    protected TokenVerificationService tokenVerificationService() {
        return tokenVerificationService;
    }

    /**
     * Provide {@link AuthenticationSuccessHandler} Spring bean autowired
     * or override this method to create new object.
     *
     * Create instance of {@link AuthenticationSuccessHandler} to return new Token when success token refresh.
     */
    protected AuthenticationSuccessHandler tokenRefreshSuccessHandler() {
        return tokenRefreshSuccessHandler;
    }
}
