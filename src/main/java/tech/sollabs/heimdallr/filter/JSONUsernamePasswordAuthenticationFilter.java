package tech.sollabs.heimdallr.filter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * username(id), password를 바탕으로 인증을 진행하기 위한 준비과정.
 * Spring Security가 전통적으로 사용하는 UsernamePasswordAuthenticationFilter를
 * 기준으로 확장하여, Request만 JSON Request를 읽어올 수 있도록 수정.
 *
 * 모든 입/출력은 JSON 형태로 주고 받습니다. 라는 기본제약 조건에 따름.
 *
 * @see UsernamePasswordAuthenticationFilter
 * @see tech.sollabs.heimdallr.configurer.JSONLoginConfigurer
 */
public class JSONUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        //try {
            Map<String, String> loginRequest = new HashMap<String, String>();// = mapper.readValue(request.getInputStream(), new TypeReference<Map<String, String>>() {});

            Authentication token = new UsernamePasswordAuthenticationToken(
                    loginRequest.get(getUsernameParameter()), loginRequest.get(getPasswordParameter()));

            return getAuthenticationManager().authenticate(token);

        /*} catch (IOException e) {
            throw new BadCredentialsException("Invalid Login Request");
        }*/
    }
}
