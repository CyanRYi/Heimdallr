package tech.sollabs.heimdallr.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.util.Assert;
import tech.sollabs.heimdallr.web.TokenRefreshFilter;
import tech.sollabs.heimdallr.web.TokenSecurityContextFilter;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

/**
 * Adds Token based authentication.
 * Authentication will process for all paths of request when has token parameterized by constructor.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link TokenSecurityContextFilter}</li>
 * <li>{@link TokenRefreshFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * No shared objects are used.
 *
 * <h2>Other Configurers Disabled</h2>
 *
 * <ul>
 * <li>{@link org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer}</li>
 * <li>{@link org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer}</li>
 * <li>{@link org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer}</li>
 * <li>{@link org.springframework.security.config.annotation.web.configurers.CsrfConfigurer}</li>
 * <li>{@link org.springframework.security.config.annotation.web.configurers.LogoutConfigurer}</li>
 * </ul>
 * <p>Configurers about Session Authentication are disabled</p>
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class TokenAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenAuthenticationConfigurer, HttpSecurity> {

    private String headerName;
    private TokenVerificationService verificationService;

    private String refreshUrl;
    private AuthenticationSuccessHandler refreshSuccessHandler;
    private AuthenticationFailureHandler refreshFailureHandler;

    /**
     * @param verificationService - TokenVerificationService verify token
     */
    public TokenAuthenticationConfigurer(TokenVerificationService verificationService) {
        this(verificationService, "Authorization");
    }

    /**
     * @param verificationService - TokenVerificationService verify token
     * @param headerName - http header name for includes Token to authentication
     */
    public TokenAuthenticationConfigurer(TokenVerificationService verificationService, String headerName) {
        Assert.notNull(verificationService, "TokenVerificationService is required.");
        this.verificationService = verificationService;
        this.headerName = headerName;
    }

    /**
     * Enable Token Refresh from specified RequestMatcher
     *
     * @param refreshUrl - Refresh URL that process Token Refresh
     * @return TokenRefreshConfigurer
     */
    public TokenAuthenticationConfigurer enableRefresh(String refreshUrl) {
        this.refreshUrl = refreshUrl;
        return this;
    }

    public TokenAuthenticationConfigurer onRefreshSuccess(AuthenticationSuccessHandler refreshSuccessHandler) {
        this.refreshSuccessHandler = refreshSuccessHandler;
        return this;
    }

    public TokenAuthenticationConfigurer onRefreshFailure(AuthenticationFailureHandler refreshFailureHandler) {
        this.refreshFailureHandler = refreshFailureHandler;
        return this;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        TokenSecurityContextFilter tokenFilter =
                new TokenSecurityContextFilter(verificationService, headerName);

        http
                .csrf().disable()
                .requestCache().disable()
                .securityContext().disable()
                .sessionManagement().disable()
                .logout().disable()
                .addFilterAt(tokenFilter, SecurityContextPersistenceFilter.class);

        if (refreshUrl != null) {
            TokenRefreshFilter refreshFilter = new TokenRefreshFilter(refreshUrl, refreshSuccessHandler);

            if (refreshFailureHandler != null) {
                refreshFilter.setAuthenticationFailureHandler(refreshFailureHandler);
            }
            http.addFilterAt(refreshFilter, LogoutFilter.class);
        }
    }
}