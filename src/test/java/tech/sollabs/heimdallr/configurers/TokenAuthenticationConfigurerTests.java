package tech.sollabs.heimdallr.configurers;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link TokenAuthenticationConfigurer}
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class TokenAuthenticationConfigurerTests {
    private AnnotationConfigWebApplicationContext context;

    @Autowired
    private TokenVerificationService mockVerificationService;

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
        this.request = new MockHttpServletRequest("GET", "/");
        this.response = new MockHttpServletResponse();
        this.chain = new MockFilterChain();
    }

    @After
    public void tearDown() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    public void authenticateWithDefaultHeaderAndValidToken() throws Exception {
        loadConfig(TokenAuthenticationConfig.class);
        doReturn(testToken)
                .when(mockVerificationService).verifyToken(VALID_TOKEN);

        request.addHeader("Authorization", VALID_TOKEN);
        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.OK.value(), response.getStatus());
    }

    @Test
    public void authenticationWithDefaultHeaderAndInvalidToken() throws Exception {
        loadConfig(TokenAuthenticationConfig.class);
        doReturn(testToken)
                .when(mockVerificationService).verifyToken(VALID_TOKEN);

        request.addHeader("Authorization", "Invalid_" + VALID_TOKEN);
        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
    }

    @Test
    public void authenticationWithInvalidHeaderAndValidToken() throws Exception {
        loadConfig(TokenAuthenticationConfig.class);
        doReturn(testToken)
                .when(mockVerificationService).verifyToken(VALID_TOKEN);

        request.addHeader("Invalid",  VALID_TOKEN);
        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
    }

    @EnableWebSecurity
    static class TokenAuthenticationConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().hasRole("USER")
                .and()
                    .apply(new TokenAuthenticationConfigurer(tokenVerificationService()));
        }

        @Bean
        public TokenVerificationService tokenVerificationService() {
            return mock(TokenVerificationService.class);
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
