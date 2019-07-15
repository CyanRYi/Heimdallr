package tech.sollabs.heimdallr.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.sollabs.heimdallr.handler.TokenIssueHandler;

import javax.servlet.FilterChain;
import java.nio.file.AccessDeniedException;

import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests {@link TokenRefreshFilter}
 *
 * @author Cyan Raphael Yi
 * @since 0.4
 */
public class TokenRefreshFilterTests {

    private TestingAuthenticationToken testToken = new TestingAuthenticationToken(
            "Cyan","Raphael Yi", "USER");

    private TokenIssueHandler mockTokenIssueHandler = mock(TokenIssueHandler.class);

    @Before
    public void setUp() {
        doNothing()
                .when(mockTokenIssueHandler)
                .issueNewToken(any(MockHttpServletRequest.class), any(MockHttpServletResponse.class), any(Authentication.class));
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testTokenRefresh() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.setServletPath("/refresh");

        TokenRefreshFilter filter = new TokenRefreshFilter("/refresh", mockTokenIssueHandler);
        SecurityContextHolder.getContext().setAuthentication(testToken);

        filter.doFilter(request, response, chain);

        verify(mockTokenIssueHandler, times(1)).issueNewToken(request, response, testToken);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testTokenRefreshWithInvalidRequestURI() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.setServletPath("/newToken");

        TokenRefreshFilter filter = new TokenRefreshFilter("/refresh", mockTokenIssueHandler);
        SecurityContextHolder.getContext().setAuthentication(testToken);

        filter.doFilter(request, response, chain);

        verify(mockTokenIssueHandler, never()).issueNewToken(request, response, testToken);
    }

    @Test(expected = AccessDeniedException.class)
    public void testTokenRefreshWithNotAuthenticatedSecurityContext() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.setServletPath("/refresh");

        TokenRefreshFilter filter = new TokenRefreshFilter("/refresh", mockTokenIssueHandler);
        TestingAuthenticationToken notAuthenticatedToken =
                new TestingAuthenticationToken(testToken.getPrincipal(), testToken.getPrincipal());
        SecurityContextHolder.getContext().setAuthentication(notAuthenticatedToken);

        filter.doFilter(request, response, chain);

        verify(mockTokenIssueHandler, never()).issueNewToken(request, response, notAuthenticatedToken);
    }
}
