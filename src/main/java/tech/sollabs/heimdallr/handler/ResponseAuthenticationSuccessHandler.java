package tech.sollabs.heimdallr.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
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
 * response of authentication success.
 *
 * @author Cyan Raphael Yi
 * @since 0.3
 */
public abstract class ResponseAuthenticationSuccessHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());
    protected int defaultResponseStatus = HttpServletResponse.SC_OK;

    protected void handle(HttpServletRequest request, HttpServletResponse response,
          Authentication authentication) throws IOException, ServletException {

        if (response.isCommitted() && logger.isDebugEnabled()) {
            logger.debug("Response has already been committed. Cannot change response");
            return;
        }

        response.setStatus(determineResponseStatus(request, authentication));

        MultiValueMap<String, String> responseHeaders = determineResponseHeader(request, authentication);

        if (responseHeaders != null) {
            for (Map.Entry<String, List<String>> headerKeyValue :
                    determineResponseHeader(request, authentication).entrySet()) {
                String headerName = headerKeyValue.getKey();

                for (String headerValue : headerKeyValue.getValue()) {
                    response.addHeader(headerName, headerValue);
                }
            }
        }

        if (!StringUtils.isEmpty(determineResponseBody(request, authentication))) {
            PrintWriter writer = response.getWriter();
            writer.write(determineResponseBody(request, authentication));
            writer.flush();
        }
    }

    /**
     * @param request
     * @param authentication
     * @return Status Code to return when success authentication
     */
    protected int determineResponseStatus(HttpServletRequest request,
          Authentication authentication) {
        return defaultResponseStatus;
    }

    /**
     * @param request
     * @param authentication
     * @return Headers to return when success authentication
     */
    protected MultiValueMap<String, String> determineResponseHeader(
            HttpServletRequest request, Authentication authentication) {
        return null;
    }

    /**
     * @param request
     * @param authentication
     * @return Body String to return when success authentication
     */
    protected String determineResponseBody(
            HttpServletRequest request, Authentication authentication) {
        return "";
    }
}
