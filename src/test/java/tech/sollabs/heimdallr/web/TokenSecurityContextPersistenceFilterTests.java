package tech.sollabs.heimdallr.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.sollabs.heimdallr.TokenVerificationService;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests {@link TokenSecurityContextPersistenceFilter}
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class TokenSecurityContextPersistenceFilterTests {

    TestingAuthenticationToken testToken = new TestingAuthenticationToken(
            "Cyan","Raphael Yi", "USER");

    private TokenVerificationService mockVerificationService = mock(TokenVerificationService.class);
    private final String VALID_TOKEN = "VALID_TOKEN_STRING";

    @Before
    public void setUp() {
        doReturn(testToken)
                .when(mockVerificationService).verifyToken(VALID_TOKEN);
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void contextIsClearedAfterChainProceeds() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);
        SecurityContextHolder.getContext().setAuthentication(testToken);

        filter.doFilter(request, response, chain);
        verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void contextIsStillClearedIfExceptionIsThrowByFilterChain() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);
        SecurityContextHolder.getContext().setAuthentication(testToken);
        doThrow(new IOException()).when(chain).doFilter(any(ServletRequest.class),
                any(ServletResponse.class));
        try {
            filter.doFilter(request, response, chain);
            fail("IOException should have been thrown");
        } catch (IOException expected) {
        } finally {
            assertNull(SecurityContextHolder.getContext().getAuthentication());
        }
    }

    @Test
    public void filterIsNotAppliedAgainIfFilterAppliedAttributeIsSet() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);

        request.setAttribute(TokenSecurityContextPersistenceFilter.FILTER_APPLIED, Boolean.TRUE);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verify(mockVerificationService, never()).verifyToken(anyString());
    }

    @Test
    public void verifyTokenSuccessfully() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("Authorization", VALID_TOKEN);

        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);

        filter.doFilter(request, response, chain);
        verify(mockVerificationService, times(1)).verifyToken(VALID_TOKEN);
    }

    @Test
    public void verifyTokenWithInvalidTokenHeader() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("Invalid", VALID_TOKEN);

        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);

        filter.doFilter(request, response, chain);
        verify(mockVerificationService, never()).verifyToken(VALID_TOKEN);
    }

    @Test
    public void verifyTokenWithInvalidTokenValue() throws Exception {
        final FilterChain chain = mock(FilterChain.class);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("Authorization", "Invalid_" + VALID_TOKEN);

        TokenSecurityContextPersistenceFilter filter =
                new TokenSecurityContextPersistenceFilter(mockVerificationService);

        filter.doFilter(request, response, chain);
        verify(mockVerificationService, never()).verifyToken(VALID_TOKEN);
    }
}
