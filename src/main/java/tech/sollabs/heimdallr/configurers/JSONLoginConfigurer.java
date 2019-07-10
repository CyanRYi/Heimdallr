package tech.sollabs.heimdallr.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationSuccessHandler;
import tech.sollabs.heimdallr.web.JSONUsernamePasswordAuthenticationFilter;

/**
 * Adds Login Process method specified by
 * {@link #createLoginProcessingUrlMatcher(String)}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link JSONUsernamePasswordAuthenticationFilter}</li>
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
 * @author Cyan Raphael Yi
 * @since 0.2
 *
 * @see org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
 * @see SimpleResponseAuthenticationSuccessHandler
 * @see SimpleResponseAuthenticationFailureHandler
 */
public class JSONLoginConfigurer
        extends AbstractAuthenticationFilterConfigurer<HttpSecurity, JSONLoginConfigurer, JSONUsernamePasswordAuthenticationFilter> {
    private RequestMatcher loginRequestMatcher;

    public JSONLoginConfigurer() {
        super(new JSONUsernamePasswordAuthenticationFilter(), null);
        super.successHandler(new SimpleResponseAuthenticationSuccessHandler());
        super.failureHandler(new SimpleResponseAuthenticationFailureHandler());
    }

    public JSONLoginConfigurer usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    public JSONLoginConfigurer passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String uri) {
        this.loginRequestMatcher = new AntPathRequestMatcher(uri, "POST");
        return loginRequestMatcher;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        super.init(http);
        http.csrf()
                .requireCsrfProtectionMatcher(new NegatedRequestMatcher(loginRequestMatcher));
    }
}