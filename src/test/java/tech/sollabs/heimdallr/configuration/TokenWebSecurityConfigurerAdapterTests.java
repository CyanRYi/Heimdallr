package tech.sollabs.heimdallr.configuration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationSuccessHandler;
import tech.sollabs.heimdallr.web.TokenRefreshFilter;
import tech.sollabs.heimdallr.web.TokenSecurityContextFilter;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link TokenWebSecurityConfigurerAdapter}.
 *
 * @author Cyan Raphael Yi
 */
public class TokenWebSecurityConfigurerAdapterTests {
    private AnnotationConfigWebApplicationContext context;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    private final String VALID_TOKEN = "VALID_TOKEN_STRING";
    private TestingAuthenticationToken testToken = new TestingAuthenticationToken(
            "Cyan","Raphael Yi", "ROLE_USER");

    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    @Before
    public void setup() {
        this.request = new MockHttpServletRequest();
        this.response = new MockHttpServletResponse();
        this.chain = new MockFilterChain();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testFilterConfiguration() throws Exception {
        loadConfig(Config.class);

        List<SecurityFilterChain> filterChains = springSecurityFilterChain.getFilterChains();
        assertEquals(1, filterChains.size());

        List<Filter> filters = filterChains.get(0).getFilters();

        assertThat(filters, hasItem(isA(TokenSecurityContextFilter.class)));
        assertThat(filters, hasItem(isA(TokenRefreshFilter.class)));
        assertThat(filters, not(hasItem(isA(LogoutFilter.class))));
        assertThat(filters, not(hasItem(isA(CsrfFilter.class))));
        assertThat(filters, not(hasItem(isA(SessionManagementFilter.class))));
        assertThat(filters, not(hasItem(isA(ConcurrentSessionFilter.class))));
        assertThat(filters, not(hasItem(isA(SecurityContextPersistenceFilter.class))));
        assertThat(filters, not(hasItem(isA(RequestCacheAwareFilter.class))));
    }

    @Test
    public void testTokenAuthentication() throws Exception {
        loadConfig(Config.class);

        request.addHeader("Authorization", "VALID_TOKEN");

        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
    }

    @Test
    public void testInvalidTokenAuthentication() throws Exception {
        loadConfig(Config.class);

        request.addHeader("Authorization", "INVALID_TOKEN");

        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.FOUND.value()));
    }

    @Test
    public void testTokenRefresh() throws Exception {
        loadConfig(Config.class);
        request.setServletPath("/refresh");
        request.addHeader("Authorization", "VALID_TOKEN");
        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
        assertThat(response.getHeader("Access-Token"), is("NEW-TOKEN"));
    }

    @Test
    public void testInvalidTokenRefresh() throws Exception {
        loadConfig(Config.class);
        request.setServletPath("/refresh");
        request.addHeader("Authorization", "INVALID_TOKEN");
        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.UNAUTHORIZED.value()));
    }

    @EnableWebMvc
    @EnableWebSecurity
    @Configuration
    static class Config extends TokenWebSecurityConfigurerAdapter {

        @Override
        protected TokenVerificationService tokenVerificationService() {
            TokenVerificationService mockVerificationService = mock(TokenVerificationService.class);

            TestingAuthenticationToken testToken = new TestingAuthenticationToken(
                    "Cyan","Raphael Yi", "ROLE_USER");

            doReturn(testToken)
                    .when(mockVerificationService).verifyToken("VALID_TOKEN");

            return mockVerificationService;
        }

        @Override
        protected AuthenticationSuccessHandler tokenRefreshSuccessHandler() {
            return new SimpleResponseAuthenticationSuccessHandler() {
                @Override
                protected MultiValueMap<String, String> determineResponseHeader(HttpServletRequest request, Authentication authentication) {
                    HttpHeaders header = new HttpHeaders();
                    header.set("Access-Token", "NEW-TOKEN");
                    return header;
                }
            };
        }
    }

    @Test
    public void testTokenAuthenticationOnCustomConfig() throws Exception {
        loadConfig(CustomConfig.class);

        request.addHeader("Authorization-token", "VALID_TOKEN");

        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
    }

    @Test
    public void testInvalidTokenAuthenticationOnCustomConfig() throws Exception {
        loadConfig(CustomConfig.class);

        request.addHeader("Authorization-token", "INVALID_TOKEN");

        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    public void testTokenRefreshOnCustomConfig() throws Exception {
        loadConfig(CustomConfig.class);
        request.setServletPath("/refresh-token");
        request.addHeader("Authorization-token", "VALID_TOKEN");
        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
        assertThat(response.getHeader("Access-Token"), is("NEW-TOKEN"));
    }

    @Test
    public void testInvalidTokenRefreshOnCustomConfig() throws Exception {
        loadConfig(CustomConfig.class);
        request.setServletPath("/refresh");
        request.addHeader("Authorization", "INVALID_TOKEN");
        springSecurityFilterChain.doFilter(request, response, chain);

        assertThat(response.getStatus(), is(HttpStatus.FORBIDDEN.value()));
    }

    @EnableWebMvc
    @EnableWebSecurity
    @Configuration
    static class CustomConfig extends TokenWebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().hasRole("USER")
                    .and()
                    .apply(new TokenAuthenticationConfigurer(tokenVerificationService(), "Authorization-Token")
                        .enableRefresh("/refresh-token")
                        .onRefreshSuccess(tokenRefreshSuccessHandler())
                        .onRefreshFailure(new SimpleResponseAuthenticationFailureHandler() {
                            @Override
                            protected int determineResponseStatus(HttpServletRequest request, AuthenticationException exception) {
                                return HttpStatus.FORBIDDEN.value();
                            }
                        })
                    );
        }

        @Override
        protected TokenVerificationService tokenVerificationService() {
            TokenVerificationService mockVerificationService = mock(TokenVerificationService.class);

            TestingAuthenticationToken testToken = new TestingAuthenticationToken(
                    "Cyan","Raphael Yi", "ROLE_USER");

            doReturn(testToken)
                    .when(mockVerificationService).verifyToken("VALID_TOKEN");

            return mockVerificationService;
        }

        @Override
        protected AuthenticationSuccessHandler tokenRefreshSuccessHandler() {
            return new SimpleResponseAuthenticationSuccessHandler() {
                @Override
                protected MultiValueMap<String, String> determineResponseHeader(HttpServletRequest request, Authentication authentication) {
                    HttpHeaders header = new HttpHeaders();
                    header.set("Access-Token", "NEW-TOKEN");
                    return header;
                }
            };
        }
    }

    private void loadConfig(Class<?>... configs) {
        this.context = new AnnotationConfigWebApplicationContext();
        this.context.register(configs);
        this.context.setServletContext(new MockServletContext());
        this.context.refresh();

        this.context.getAutowireCapableBeanFactory().autowireBean(this);
    }
}
