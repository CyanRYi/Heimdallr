package tech.sollabs.heimdallr;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for simple presentation of String case of Authentication Token(i.e jwt or oAuth access token).
 * <p>
 * The <code>principal</code> should be set with an <code>Object</code> that provides identification.
 * The simplest such <code>Object</code> to use is <code>String</code>.
 *
 * @author Cyan Raphael Yi
 * @since 0.2
 */
public class TokenAuthentication extends AbstractAuthenticationToken {

    private String token;
    private Object principal;

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>TokenAuthentication</code> by Unknown Token, as the {@link #isAuthenticated()}
     * will return <code>false</code>.
     *
     */
    public TokenAuthentication(String token) {
        super(null);
        Assert.notNull(token, "Token Cannot be null");
        this.token = token;
        setAuthenticated(false);
    }

    /**
     * This constructor should only be used by <code>TokenVerificationService</code>
     * implementations that are satisfied with producing a trusted
     * (i.e. {@link #isAuthenticated()} = <code>true</code>) authentication token.
     *
     * @param principal
     * @param authorities
     */
    public TokenAuthentication(Object principal, Collection<GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);

    }

    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return getToken();
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }
}