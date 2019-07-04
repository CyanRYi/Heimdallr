package tech.sollabs.heimdallr.configurer;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tech.sollabs.heimdallr.filter.TokenAuthenticationFilter;
import tech.sollabs.heimdallr.filter.TokenRefreshFilter;

/**
 * JWT를 통한 인증(기본)과 JWT refresh(옵션)를 위한 Spring Security 설정자
 *
 * @param <T>
 * @see TokenAuthenticationFilter
 * @see TokenRefreshFilter
 */
public class TokenAuthenticationConfigurer<T extends HttpSecurityBuilder<T>>
        extends AbstractAuthenticationFilterConfigurer<T, TokenAuthenticationConfigurer<T>, TokenAuthenticationFilter> {

    private TokenRefreshFilter jwtRefreshFilter = null;
    private AuthenticationSuccessHandler refreshSuccessHandler;
    private AuthenticationFailureHandler refreshFailureHandler;

    /**
     * JWT 인증을 위해 토큰을 가져올 Header Name을 필수로 요한다.
     *
     * @param jwtHeaderName - JWT를 포함하고 있는 Header Name
     */
    public TokenAuthenticationConfigurer(String jwtHeaderName) {
        super(new TokenAuthenticationFilter(jwtHeaderName), null);
    }

    /**
     * 모든 요청에 대해 인증과정을 진행한다.
     * 실제 인증 성공 여부는 JwtAuthenticationFilter, JwtAuthenticationProvider에서 진행되며
     * 인증 실패시에는 Security Filter Proxy에 의해 다음 순번의 인증 방식으로 진행된다.
     *
     * @param loginProcessingUrl
     * @return
     */
    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher("/**");
    }

    /**
     * 특정 요청 조건에 의해 token refresh를 가능하도록 한다.
     *
     * @param tokenRefreshRequestMatcher - refresh 요청을 진행할 Matcher
     * @return self
     */
    public TokenAuthenticationConfigurer<T> enableRefresh(RequestMatcher tokenRefreshRequestMatcher) {

        this.jwtRefreshFilter = new TokenRefreshFilter(tokenRefreshRequestMatcher);
        return this;
    }

    /**
     * refresh 성공시의 SuccessHandler를 등록한다.
     *
     * TODO: 별도 Open Source Project에서 AuthenticationSuccessHandler를 구현한 TokenIssueHandler(String tokenHeaderName) 으로 구현한다.
     *
     * @param successHandler - refresh 성공시 진행할 SuccessHandler
     * @return self
     */
    public TokenAuthenticationConfigurer<T> onRefreshSuccess(AuthenticationSuccessHandler successHandler) {

        this.refreshSuccessHandler = successHandler;
        return this;
    }

    /**
     * refresh 실패시 작업을 수행할 FailureHandler를 등록한다.
     * TokenRefreshFilter는 설정에 의해  TokenAuthenticaionFilter 직후에 수행되므로
     * 기본적으로는 토큰 생성에 실패할 일은 없으나, Spring Security의 복잡한 구성상 여지는 매우 높다.
     *
     * @param failureHandler - refresh 성공시 진행할 SuccessHandler
     * @return self
     */
    public TokenAuthenticationConfigurer<T> onRefreshFailure(AuthenticationFailureHandler failureHandler) {

        this.refreshFailureHandler = failureHandler;
        return this;
    }

    /**
     * 기본적인 수행에 추가하여 JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 이후에 등록한다.
     * 만약 Refresh에 관한 설정이 추가되어 있으면, JwtRefreshFilter를 그 이후에 추가한다.
     */
    @Override
    public void init(T http) throws Exception {
        super.init(http);
        http.addFilterAfter(super.getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        if (jwtRefreshFilter != null) {
            jwtRefreshFilter.setAuthenticationSuccessHandler(refreshSuccessHandler);
            jwtRefreshFilter.setAuthenticationFailureHandler(refreshFailureHandler);
            http.addFilterAfter(jwtRefreshFilter, super.getAuthenticationFilter().getClass());
        }
    }
}