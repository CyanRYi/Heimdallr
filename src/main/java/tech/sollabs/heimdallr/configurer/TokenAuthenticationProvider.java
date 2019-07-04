package tech.sollabs.heimdallr.configurer;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import tech.sollabs.heimdallr.TokenAuthentication;

/**
 * JWT를 사용하는 인증제공자
 * 인증 이전의 JwtAuthentication 객체를 사용하며, 인증 이후 새로운 JwtAuthentication 객체를 반환한다.
 *
 * @see tech.sollabs.heimdallr.filter.TokenAuthenticationFilter
 */
@Component
public class TokenAuthenticationProvider implements AuthenticationProvider {

    @Override
    public boolean supports(Class<?> authentication) {
        return TokenAuthentication.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        return (TokenAuthentication) authentication;
/*
        try {
            // TODO : UserAccountService를 사용하는 대신 별도의 TokenVerifier 형식을 통해 우효성 검증.
            DecodedJWT jwt = JWTUtil.verifyJwt(jwtAuth.getCredentials());
            UserAccount user = userAccountService.getUserAccountById(jwt.getSubject());

            return new JwtAuthentication(user.getId(), Collections.emptySet());
        } catch (ResourceNotFoundException | TokenExpiredException validityException) {
            throw new InvalidJwtException(validityException.getMessage());
        } catch (JWTVerificationException e) {
            throw new InvalidJwtException("Invalid JWT");
        }*/
    }
}