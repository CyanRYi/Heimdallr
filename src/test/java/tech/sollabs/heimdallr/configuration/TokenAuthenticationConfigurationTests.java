package tech.sollabs.heimdallr.configuration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tech.sollabs.heimdallr.handler.TokenIssueHandler;
import tech.sollabs.heimdallr.web.TokenRefreshFilter;
import tech.sollabs.heimdallr.web.TokenSecurityContextFilter;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

import javax.servlet.Filter;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Tests for {@link TokenAuthenticationConfiguration}.
 *
 * @author Cyan Raphael Yi
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class TokenAuthenticationConfigurationTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    private Authentication authentication =
            new TestingAuthenticationToken("user", "password",
                    AuthorityUtils.createAuthorityList("ROLE_USER"));

    @Before
    public void setUp() {
        this.mockMvc = MockMvcBuilders
                .webAppContextSetup(context).build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void authenticationPrincipalResolved() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);

        mockMvc.perform(get("/authentication-principal"))
                .andExpect(content().string(is(authentication.getPrincipal())));
    }

    @Test
    public void testFilterConfiguration() throws Exception {

        FilterChainProxy filterChainProxy = context.getBean(FilterChainProxy.class);
        List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
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

    @RestController
    static class TestController {

        @RequestMapping("/authentication-principal")
        public String authenticationPrincipal(@AuthenticationPrincipal String principal) {
            return principal;
        }
    }

    @EnableWebMvc
    @Configuration
    @Import(TokenAuthenticationConfiguration.class)
    static class Config {
        @Bean
        public TestController testController() {
            return new TestController();
        }

        @Bean
        public TokenVerificationService verificationService() {
            return mock(TokenVerificationService.class);
        }

        @Bean
        public TokenIssueHandler tokenIssueHandler() {
            return mock(TokenIssueHandler.class);
        }
    }
}
