package tech.sollabs.heimdallr.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import tech.sollabs.heimdallr.filter.TokenRefreshFilter;
import tech.sollabs.heimdallr.web.TokenSecurityContextPersistenceFilter;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

import javax.servlet.Filter;

/**
 * Adds Token based authentication.
 * Authentication will process for all paths of request when has token parameterized by constructor.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link TokenSecurityContextPersistenceFilter}</li>
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
 * </ul>
 * <p>Configurers about Session Authentication are disabled</p>
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class TokenAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenAuthenticationConfigurer, HttpSecurity> {

    private Filter tokenFilter;

    /**
     * @param verificationService - TokenVerificationService verify token
     */
    public TokenAuthenticationConfigurer(TokenVerificationService verificationService) {
        this.tokenFilter = new TokenSecurityContextPersistenceFilter(verificationService);
    }

    /**
     * @param verificationService - TokenVerificationService verify token
     * @param headerName - http header name for includes Token to authentication
     */
    public TokenAuthenticationConfigurer(TokenVerificationService verificationService, String headerName) {
        this.tokenFilter = new TokenSecurityContextPersistenceFilter(verificationService, headerName);
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .requestCache().disable()
                .securityContext().disable()
                .sessionManagement().disable()
                .logout().disable()
                .addFilterAt(tokenFilter, SecurityContextPersistenceFilter.class);
    }
}