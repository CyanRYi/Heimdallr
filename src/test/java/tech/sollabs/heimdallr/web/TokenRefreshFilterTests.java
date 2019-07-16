package tech.sollabs.heimdallr.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import java.io.IOException;

import static org.junit.Assert.*;
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

    private AuthenticationSuccessHandler mockTokenIssueHandler = mock(AuthenticationSuccessHandler.class);

    @Before
    public void setUp() throws IOException, ServletException {
        doNothing()
                .when(mockTokenIssueHandler)
                .onAuthenticationSuccess(any(MockHttpServletRequest.class), any(MockHttpServletResponse.class), any(Authentication.class));
    }

    @After
    public void tearDown() {
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

        verify(mockTokenIssueHandler, times(1)).onAuthenticationSuccess(request, response, testToken);
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

        verify(mockTokenIssueHandler, never()).onAuthenticationSuccess(request, response, testToken);
    }

    @Test
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
        assertEquals(response.getStatus(), HttpStatus.UNAUTHORIZED.value());
        verify(mockTokenIssueHandler, never()).onAuthenticationSuccess(request, response, notAuthenticatedToken);
    }
}
