package tech.sollabs.heimdallr.handler;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Issue new Token from {@link tech.sollabs.heimdallr.web.TokenRefreshFilter}
 * when requested specified token refresh url and request already authenticated
 *
 * @see tech.sollabs.heimdallr.web.TokenRefreshFilter
 */
public interface TokenIssueHandler {

    void issueNewToken(HttpServletRequest request,
          HttpServletResponse response, Authentication authentication);
}
