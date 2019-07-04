package tech.sollabs.heimdallr.filter;

import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import tech.sollabs.heimdallr.TokenAuthentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT를 사용하여 Access Control을 제공한다.
 *
 * sign-in과 구분하기 위하여 별도의 Authentication 구현체(JwtAuthentication)를 사용하며
 * 인증 자체도 별도의 AuthenticationProvider 구현체(JwtAuthenticationProvider)를 통해 진행한다.
 *
 * JwtAuthenticationConfigurer를 통해 Spring Security와 동일한 설정을 제공.
 *
 * @see tech.sollabs.heimdallr.configurer.TokenAuthenticationConfigurer
 * @see TokenAuthentication
 */
public class TokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final String AUTHORIZATION_HEADER_NAME;

    public TokenAuthenticationFilter(String jwtHeaderName) {
        super(new AntPathRequestMatcher("/**"));
        this.AUTHORIZATION_HEADER_NAME = jwtHeaderName;
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {

        String apiKey = request.getHeader(AUTHORIZATION_HEADER_NAME);
        return !StringUtils.isEmpty(apiKey);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String apiKey = request.getHeader(AUTHORIZATION_HEADER_NAME);

        TokenAuthentication tokenAuthentication = new TokenAuthentication(apiKey, new WebAuthenticationDetails(request));

        return getAuthenticationManager().authenticate(tokenAuthentication);
    }

    /**
     * 이 Filter를 통해 인증이 성공한 경우에는 그래도 Servlet Filter Chain을 이용해야 하므로
     * successfulAuthentication를 override 하여 그대로 Filter Chain을 수행한다.
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
                    + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        if (this.eventPublisher != null) {
            //TODO : Token 인증에 대해 별도의 Authentication Event 작성. 별도의 Open Source Project로 진행
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                    authResult, this.getClass()));
        }

        chain.doFilter(request, response);
    }
}