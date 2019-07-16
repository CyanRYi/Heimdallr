package tech.sollabs.heimdallr.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.GenericFilterBean;
import tech.sollabs.heimdallr.web.context.TokenVerificationService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

/**
 * This filter switch implementation of {@link org.springframework.security.web.context.SecurityContextPersistenceFilter}
 * token instead session.
 *
 * This class uses {@link TokenVerificationService} instead {@link SecurityContextRepository}
 * cause of token is valid for each request
 */
public class TokenSecurityContextFilter extends GenericFilterBean {

    static final String FILTER_APPLIED = "__token_security_scpf_applied";
    private final String TOKEN_HEADER_NAME;
    private TokenVerificationService verificationService;

    public TokenSecurityContextFilter(TokenVerificationService verificationService, String headerName) {
        this.verificationService = verificationService;
        this.TOKEN_HEADER_NAME = headerName;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (request.getAttribute(FILTER_APPLIED) != null) {
            // ensure that filter is only applied once per request
            chain.doFilter(request, response);
            return;
        }

        final boolean debug = logger.isDebugEnabled();

        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        SecurityContext contextBeforeChainExecution = readSecurityContextFromHeader(request);

        try {
            SecurityContextHolder.setContext(contextBeforeChainExecution);
            chain.doFilter(request, response);
        }
        finally {
            // Crucial removal of SecurityContextHolder contents - do this before anything
            // else.
            SecurityContextHolder.clearContext();
            request.removeAttribute(FILTER_APPLIED);

            if (debug) {
                logger.debug("SecurityContextHolder now cleared, as request processing completed");
            }
        }
    }

    /**
     * @param request the current http request
     */
    private SecurityContext readSecurityContextFromHeader(HttpServletRequest request) {
        final boolean debug = logger.isDebugEnabled();

        if (!containsContext(request)) {
            if (debug) {
                logger.debug("No token header currently exists");
            }

            return SecurityContextHolder.createEmptyContext();
        }

        Enumeration<String> tokenHeaders = request.getHeaders(TOKEN_HEADER_NAME);
        String token = tokenHeaders.nextElement();

        if (tokenHeaders.hasMoreElements()) {
            if (logger.isWarnEnabled()) {
                logger.warn("Token Header name : '"
                        + TOKEN_HEADER_NAME
                        + "' has two or more values. "
                        + token
                        + " is use for Security and others will be ignore.");
            }
        }

        if (debug) {
            logger.debug("Obtained a valid SecurityContext from "
                    + TOKEN_HEADER_NAME + ": '" + token + "'");
        }

        Authentication authentication = verificationService.verifyToken(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return SecurityContextHolder.getContext();
    }

    private boolean containsContext(HttpServletRequest request) {
        return request.getHeaders(TOKEN_HEADER_NAME).hasMoreElements();
    }
}
