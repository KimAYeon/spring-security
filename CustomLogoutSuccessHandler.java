package net.cj.ethics.admin.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        if (authentication != null && authentication.getDetails() != null) {
            try {
                httpServletRequest.getSession().invalidate();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        httpServletResponse.sendRedirect("/sample/sampleLogin");
    }
}
