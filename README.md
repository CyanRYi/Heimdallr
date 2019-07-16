# Heimdallr
Heimdallr - Spring Extension 4th Series. Spring Security Token Authentication Configurer   
Heimdallr name stemmed from the Norse Mythology. - [wikipedia](https://en.wikipedia.org/wiki/Heimdallr)

## Requirement

* spring-web : 4.2.0.RELEASE
* spring-security : 4.2.0.RELEASE
* servlet-api : 3.0.1

## Features
1. Heimdallr provides Token-based-authentication like JWT simply.
- Session-based-authentication will be disabled when using Heimdallr.
- Request includes Token makes Authentication automatically.
- Can refresh token with Valid token and specified request.

## usage
1. Create Configuration extends TokenWebSecurityConfigurerAdapter instead of WebSecurityConfigurerAdapter.
1. Overrides method
    - tokenVerificationService() returns TokenVerificationService that verify Token and return Authentication
    - tokenRefreshSuccessHandler() returns AuthenticationSuccessHandler to return new Token when refresh success
    - (Optional) tokenRefreshFailureHandler() returns AuthenticationFailureHandler to return error when refresh failed 

```java
@EnableWebSecurity
public class Config extends TokenWebSecurityConfigurerAdapter {
    
    /**
    * Override if you need customize Options, configure HttpSecurity and call super(http)
    */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super(http);
        http.authorizeRequests()
                .anyRequest().hasRole("USER");                
    }

    @Override
    protected TokenVerificationService tokenVerificationService() {
        return new TokenVerificationService() {
            @Override
            public Authentication verifyToken(String token) throws InvalidTokenException {
                if (token is invalid) {
                    throw new InvalidTokenException("Token is Invalid");
                }
                
                return new TokenAuthentication("principal", AuthorityUtils.createAuthorityList("Authority1", "Authority2" ...));
            }
        };
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

            @Override
            protected String determineResponseBody(HttpServletRequest request, Authentication authentication) {
                return String.format("{ \"Access-Token\" : \"%s\" }", "NEW-TOKEN");
            }
        };
    }
}
```


### If you cannot use TokenWebSecurityConfigurerAdapter for various reason
1. Apply TokenAuthenticationConfigurer override configure(http) method.
    - Constructor of TokenAuthenticationConfigurer need TokenVerificationService parameter
    - String headerName parameter is optional(default value is "Authorization")

```java
@EnableWebSecurity
public class Config extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().hasRole("USER")
            // ... configure your options ...
            .apply(new TokenAuthenticationConfigurer(tokenVerificationService(), "Authorization")
                .enableRefresh("/refresh")  // Default token refresh url is "/refresh"
                .onRefreshSuccess(tokenRefreshSuccessHandler())
                .onRefreshFailure(new SimpleResponseAuthenticationFailureHandler() {        // Default Failure Handler is return response status 401-Unauthorized
                    @Override
                    protected int determineResponseStatus(HttpServletRequest request, AuthenticationException exception) {
                        return HttpStatus.FORBIDDEN.value();
                    }
                })
            );         
    }

    private TokenVerificationService tokenVerificationService() {
        // ...
    }

    private AuthenticationSuccessHandler tokenRefreshSuccessHandler() {
        // ...
    }
}


```
## Source Code Repository
(https://github.com/CyanRYi/Heimdallr)

## License
MIT

### Contributor
@Cyan Raphael Yi