package tech.sollabs.heimdallr.handler;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface TokenIssueHandler {

    void issueNewToken(HttpServletRequest request,
          HttpServletResponse response, Authentication authentication);
}
