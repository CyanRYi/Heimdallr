package tech.sollabs.heimdallr.filter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import tech.sollabs.heimdallr.TokenAuthentication;
import tech.sollabs.heimdallr.exception.InvalidTokenException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT refresh를 위한 Filter.
 * 다양한 설정은 JwtAuthenticationConfigurer를 사용하여 Spring Security 설정과 같은 방식으로 처리.
 *
 * TODO : Token Refresh에 대해 Authentication Event 작성. 별도의 Open Source Project로 진행
 *
 * @see tech.sollabs.heimdallr.configurer.TokenAuthenticationConfigurer
 * @see TokenAuthenticationFilter
 * @see TokenAuthentication
 */
public class TokenRefreshFilter extends AbstractAuthenticationProcessingFilter {

    public TokenRefreshFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    /**
     * Authentication 객체가 JwtAuthentication이고, 성공적으로 인증되었을 경우에만 refresh 수행.
     * 기본 설정 상에서는 발생하지 않으나, 추가적인 Spring Security 확장에 의해 여지가 있음.
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!TokenAuthentication.class.isAssignableFrom(authentication.getClass())
                || !authentication.isAuthenticated()) {
            throw new InvalidTokenException("Error occur while token refreshing");
        }

        return authentication;
    }
}