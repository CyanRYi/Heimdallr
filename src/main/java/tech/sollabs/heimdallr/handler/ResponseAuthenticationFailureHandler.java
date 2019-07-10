package tech.sollabs.heimdallr.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

/**
 * Abstract class for return status, headers, body for
 * response of authentication failure.
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public abstract class ResponseAuthenticationFailureHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());
    protected int defaultResponseStatus = HttpServletResponse.SC_UNAUTHORIZED;

    protected void handle(HttpServletRequest request, HttpServletResponse response,
          AuthenticationException exception) throws IOException, ServletException {

        if (response.isCommitted() && logger.isDebugEnabled()) {
            logger.debug("Response has already been committed. Cannot change response");
            return;
        }

        response.setStatus(determineResponseStatus(request, exception));

        MultiValueMap<String, String> responseHeaders = determineResponseHeader(request, exception);

        if (responseHeaders != null) {
            for (Map.Entry<String, List<String>> headerKeyValue :
                    determineResponseHeader(request, exception).entrySet()) {
                String headerName = headerKeyValue.getKey();

                for (String headerValue : headerKeyValue.getValue()) {
                    response.addHeader(headerName, headerValue);
                }
            }
        }

        if (!StringUtils.isEmpty(determineResponseBody(request, exception))) {
            PrintWriter writer = response.getWriter();
            writer.write(determineResponseBody(request, exception));
            writer.flush();
        }
    }

    /**
     * @param request
     * @param exception AuthenticationException
     * @return Status Code to return when fail authentication
     */
    protected int determineResponseStatus(HttpServletRequest request,
          AuthenticationException exception) {
        return defaultResponseStatus;
    }

    /**
     * @param request
     * @param exception AuthenticationException
     * @return Headers to return when fail authentication
     */
    protected MultiValueMap<String, String> determineResponseHeader(
            HttpServletRequest request, AuthenticationException exception) {
        return null;
    }

    /**
     * @param request
     * @param exception AuthenticationException
     * @return Body String to return when fail authentication
     */
    protected String determineResponseBody(
            HttpServletRequest request, AuthenticationException exception) {
        return "";
    }
}
