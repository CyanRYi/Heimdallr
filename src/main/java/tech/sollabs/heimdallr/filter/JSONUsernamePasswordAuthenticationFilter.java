package tech.sollabs.heimdallr.filter;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Convert from JSON login request to UsernamePasswordAuthenticationToken
 *
 * TODO : check SecurityJackson2Modules and UsernamePasswordAuthenticationTokenDeserializer
 *
 * @author Cyan Raphael Yi
 * @since 0.2
 * @see UsernamePasswordAuthenticationFilter
 * @see tech.sollabs.heimdallr.configurer.JSONLoginConfigurer
 */
public class JSONUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        try {
            JSONObject loginRequest = (JSONObject) new JSONParser().parse(request.getReader());

            Authentication token = new UsernamePasswordAuthenticationToken(
                    loginRequest.get(getUsernameParameter()), loginRequest.get(getPasswordParameter()));

            return getAuthenticationManager().authenticate(token);
        } catch (ParseException | IOException e) {
            throw new BadCredentialsException("Invalid Login Request");
        }
    }
}
