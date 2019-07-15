package tech.sollabs.heimdallr.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import tech.sollabs.heimdallr.handler.TokenIssueHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.AccessDeniedException;

/**
 * Refresh Access Token.
 * When request matches {@link #requiresRefresh(HttpServletRequest)} and already Authenticated,
 * issue new Token by {@link TokenIssueHandler#issueNewToken(HttpServletRequest, HttpServletResponse, Authentication)}
 *
 * @see tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer
 * @see tech.sollabs.heimdallr.web.TokenSecurityContextFilter
 * @see TokenIssueHandler
 */
public class TokenRefreshFilter extends GenericFilterBean {

    private RequestMatcher refreshRequestMatcher;
    private TokenIssueHandler tokenIssueHandler;

    public TokenRefreshFilter(String refreshUrl, TokenIssueHandler tokenIssueHandler) {
        Assert.isTrue(StringUtils.hasLength(refreshUrl),
                refreshUrl + " isn't a valid URL");
        Assert.notNull(tokenIssueHandler, "TokenIssueHandler is required.");
        this.refreshRequestMatcher = new AntPathRequestMatcher(refreshUrl);
        this.tokenIssueHandler = tokenIssueHandler;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (requiresRefresh(request)) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                throw new AccessDeniedException("Token Refreshing must be process after Authentication");
            }

            tokenIssueHandler.issueNewToken(request, response, authentication);

            SecurityContextHolder.clearContext();
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Allow subclasses to modify when a refresh should take place.
     *
     * @param request the request
     *
     * @return <code>true</code> if refresh should occur, <code>false</code> otherwise
     */
    protected boolean requiresRefresh(HttpServletRequest request) {
        return refreshRequestMatcher.matches(request);
    }
}