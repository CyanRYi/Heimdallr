package tech.sollabs.heimdallr.configurer;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tech.sollabs.heimdallr.filter.JSONUsernamePasswordAuthenticationFilter;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationSuccessHandler;

/**
 * FormLoginConfigurer과 대비하여 JSON Format의 login 요청을 처리하기 위한 설정자.
 *
 * TODO : AbstractHttpConfigurer를 직접 확장하고 기본 Success, Failure Handler를 관리.
 *
 * @author Cyan Raphael Yi
 * @since 0.2
 * @see org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
 * @see JSONUsernamePasswordAuthenticationFilter
 * @see SimpleResponseAuthenticationSuccessHandler
 * @see SimpleResponseAuthenticationFailureHandler
 */
public class JSONLoginConfigurer<T extends HttpSecurityBuilder<T>>
        extends AbstractAuthenticationFilterConfigurer<T, JSONLoginConfigurer<T>, JSONUsernamePasswordAuthenticationFilter> {

    public JSONLoginConfigurer(String defaultLoginProcessingUrl) {
        super(new JSONUsernamePasswordAuthenticationFilter(), defaultLoginProcessingUrl);
        super.successHandler(new SimpleResponseAuthenticationSuccessHandler());
        super.failureHandler(new SimpleResponseAuthenticationFailureHandler());
    }

    public JSONLoginConfigurer<T> usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    public JSONLoginConfigurer<T> passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String uri) {
        return new AntPathRequestMatcher(uri, "POST");
    }
}