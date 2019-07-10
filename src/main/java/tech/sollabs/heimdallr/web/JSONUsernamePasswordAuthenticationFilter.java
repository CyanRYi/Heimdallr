package tech.sollabs.heimdallr.web;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.sollabs.heimdallr.configurers.JSONLoginConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Convert from JSON login request to UsernamePasswordAuthenticationToken
 *
 * TODO : check {@link org.springframework.security.jackson2.SecurityJackson2Modules} and UsernamePasswordAuthenticationTokenDeserializer
 *
 * @author Cyan Raphael Yi
 * @since 0.2
 * @see UsernamePasswordAuthenticationFilter
 * @see JSONLoginConfigurer
 */
public class JSONUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return MediaType.APPLICATION_JSON.isCompatibleWith(MediaType.parseMediaType(request.getContentType()));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        try {
            JSONObject loginRequest;

            if (request.getContentLength() > 0) {
                loginRequest = (JSONObject) new JSONParser().parse(request.getReader());
            } else {
                loginRequest = new JSONObject();
            }

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    loginRequest.get(getUsernameParameter()), loginRequest.get(getPasswordParameter()));
            setDetails(request, token);

            return getAuthenticationManager().authenticate(token);
        } catch (ParseException | IOException e) {
            throw new BadCredentialsException("Invalid Login Request");
        }
    }
}
