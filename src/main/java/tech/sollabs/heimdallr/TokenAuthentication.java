package tech.sollabs.heimdallr;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;

import java.util.Collection;

public class TokenAuthentication extends AbstractAuthenticationToken {

    private String encodedJwt;
    private String id;

    /**
     * 인증되기 이전의 정보를 담는다.
     * encodedJwt를 담아 Provider로 전달하기 위한 목적.
     *
     * @param encodedJwt - Encoding 상태의 JWT String
     * @param details - 인증 관련 Details 항목
     */
    public TokenAuthentication(String encodedJwt, WebAuthenticationDetails details) {
        super(null);
        Assert.notNull(encodedJwt, "Token Cannot be null");
        this.encodedJwt = encodedJwt;
        setAuthenticated(false);
        super.setDetails(details);
    }

    /**
     * 인증 이후의 subject와 권한을 담는다.
     *
     * @param id
     * @param authorities
     */
    public TokenAuthentication(String id, Collection<GrantedAuthority> authorities) {
        super(authorities);
        this.id = id;
        super.setAuthenticated(true);
    }

    public String getCredentials() {
        return encodedJwt;
    }

    public String getPrincipal() {
        return id;
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