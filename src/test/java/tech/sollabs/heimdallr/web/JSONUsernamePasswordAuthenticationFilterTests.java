package tech.sollabs.heimdallr.web;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.ServletException;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests {@link JSONUsernamePasswordAuthenticationFilter}
 *
 * This tests extends {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilterTests}
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class JSONUsernamePasswordAuthenticationFilterTests {

    @Test
    public void testNormalOperation() throws Exception {
        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "Cyan",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "Raphael Yi");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertNotNull(result);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testNullPasswordHandledGracefully() throws Exception {
        String content = String.format("{\"%s\": \"%s\"}",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "Cyan");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        assertNotNull(filter.attemptAuthentication(request, new MockHttpServletResponse()));
    }

    @Test
    public void testNullUsernameHandledGracefully() throws Exception {
        String content = String.format("{\"%s\": \"%s\"}",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "Raphael Yi");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        assertNotNull(filter.attemptAuthentication(request, new MockHttpServletResponse()));
    }

    @Test
    public void testUsingDifferentParameterNamesWorksAsExpected() throws ServletException {
        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "x", "Cyan",
                "y", "Raphael Yi");

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.setUsernameParameter("x");
        filter.setPasswordParameter("y");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertNotNull(result);
        assertEquals("127.0.0.1", ((WebAuthenticationDetails) result.getDetails()).getRemoteAddress());
    }

    @Test
    public void testSpacesAreTrimmedCorrectlyFromUsername() throws Exception {
        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "Cyan",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY, "Raphael Yi");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
        assertEquals("Cyan", result.getName());
    }

    @Test(expected = AuthenticationException.class)
    public void testFailedAuthenticationThrowsException() {
        String content = String.format("{\"%s\": \"%s\"}",
                JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY, "Cyan");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/");
        request.setContent(content.getBytes());
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(
                new BadCredentialsException(""));
        filter.setAuthenticationManager(am);

        filter.attemptAuthentication(request, new MockHttpServletResponse());
    }

    /**
     * SEC-571
     */
    @Test
    public void noSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAllowSessionCreation(false);
        filter.setAuthenticationManager(createAuthenticationManager());

        filter.attemptAuthentication(request, new MockHttpServletResponse());

        assertNull(request.getSession(false));
    }

    @Test
    public void passedByFormLoginRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        request.addParameter(JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY,"Cyan");
        request.addParameter(JSONUsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY,"Raphael Yi");

        JSONUsernamePasswordAuthenticationFilter filter = new JSONUsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        assertFalse(filter.requiresAuthentication(request, new MockHttpServletResponse()));
    }

    private AuthenticationManager createAuthenticationManager() {
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenAnswer(
                new Answer<Authentication>() {
                    public Authentication answer(InvocationOnMock invocation)
                            throws Throwable {
                        return (Authentication) invocation.getArguments()[0];
                    }
                });

        return am;
    }
}
