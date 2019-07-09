package tech.sollabs.heimdallr.configurers;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationFailureHandler;
import tech.sollabs.heimdallr.handler.SimpleResponseAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;

/**
 * Tests {@link JSONLoginConfigurer}
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public class JSONLoginConfigurerTests {
    private AnnotationConfigWebApplicationContext context;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    @Before
    public void setup() {
        this.request = new MockHttpServletRequest();
        this.request.setMethod("GET");
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
    public void loginSuccessWIthDefaultUsernameAndPasswordParameters() throws Exception {
        loadConfig(JSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "username", "Cyan", "password", "Raphael Yi");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.OK.value(), response.getStatus());
    }

    @Test
    public void loginFailureWithInvalidUsername() throws Exception {
        loadConfig(JSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "username", "Invalid", "password", "Raphael Yi");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
    }

    @Test
    public void loginFailureWithInvalidPassword() throws Exception {
        loadConfig(JSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "username", "Cyan", "password", "Invalid");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
    }

    @EnableWebSecurity
    static class JSONLoginConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().hasRole("USER")
                .and()
                    .apply(new JSONLoginConfigurer());
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser("Cyan")
                    .password("Raphael Yi")
                    .authorities(AuthorityUtils.createAuthorityList("USER"));
        }
    }

    @Test
    public void customLoginSuccessWIthDefaultUsernameAndPasswordParameters() throws Exception {
        loadConfig(CustomJSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "id", "Cyan", "pw", "Raphael Yi");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.ACCEPTED.value(), response.getStatus());
        assertEquals("Login Success", response.getContentAsString());
    }

    @Test
    public void customLoginFailureWithInvalidUsername() throws Exception {
        loadConfig(CustomJSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "id", "Invalid", "pw", "Raphael Yi");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
        assertEquals("Login Failed", response.getContentAsString());
    }

    @Test
    public void customLoginFailureWithInvalidPassword() throws Exception {
        loadConfig(CustomJSONLoginConfig.class);

        String content = String.format("{\"%s\": \"%s\", \"%s\": \"%s\"}",
                "id", "Cyan", "pw", "Invalid");

        request.setServletPath("/login");
        request.setMethod("POST");
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content.getBytes());

        this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

        assertEquals(HttpStatus.FORBIDDEN.value(), response.getStatus());
        assertEquals("Login Failed", response.getContentAsString());
    }

    @EnableWebSecurity
    static class CustomJSONLoginConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().hasRole("USER")
                .and()
                    .apply(new JSONLoginConfigurer())
                    .usernameParameter("id")
                    .passwordParameter("pw")
                    .successHandler(new SimpleResponseAuthenticationSuccessHandler() {
                        @Override
                        protected int determineResponseStatus(HttpServletRequest request, Authentication authentication) {
                            return HttpStatus.ACCEPTED.value();
                        }

                        @Override
                        protected String determineResponseBody(HttpServletRequest request, Authentication authentication) {
                            return "Login Success";
                        }
                    })
                    .failureHandler(new SimpleResponseAuthenticationFailureHandler() {
                        @Override
                        protected int determineResponseStatus(HttpServletRequest request, AuthenticationException exception) {
                            return HttpStatus.FORBIDDEN.value();
                        }

                        @Override
                        protected String determineResponseBody(HttpServletRequest request, AuthenticationException exception) {
                            return "Login Failed";
                        }
                    });
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser("Cyan")
                    .password("Raphael Yi")
                    .authorities(AuthorityUtils.createAuthorityList("USER"));
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
