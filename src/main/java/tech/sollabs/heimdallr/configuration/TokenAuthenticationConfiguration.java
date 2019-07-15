package tech.sollabs.heimdallr.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import tech.sollabs.heimdallr.configurers.TokenAuthenticationConfigurer;
import tech.sollabs.heimdallr.handler.TokenIssueHandler;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

/**
 * Default Configuration for Token Authentication
 * When {@link TokenVerificationService} and {@link TokenIssueHandler} beans are not exists,
 * Exception will be thrown from {@link TokenAuthenticationConfigurer}
 *
 * @author Cyan Raphael Yi
 * @since 0.4.0
 *
 * @see TokenAuthenticationConfigurer
 */
@EnableWebSecurity
@Configuration
public class TokenAuthenticationConfiguration extends WebSecurityConfigurerAdapter {

    private TokenVerificationService tokenVerificationService;
    private TokenIssueHandler tokenIssueHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .apply(new TokenAuthenticationConfigurer(tokenVerificationService)
                        .enableRefresh("/refresh")
                        .onTokenRefresh(tokenIssueHandler));
    }

    @Autowired(required = false)
    public void setTokenVerificationService(TokenVerificationService tokenVerificationService) {
        this.tokenVerificationService = tokenVerificationService;
    }

    @Autowired(required = false)
    public void setTokenIssueHandler(TokenIssueHandler tokenIssueHandler) {
        this.tokenIssueHandler = tokenIssueHandler;
    }
}
