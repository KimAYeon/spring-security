package net.cj.ethics.admin.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();
    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if(savedRequest == null) {
            response.sendRedirect("/main");   //로그인 하기 전의 페이지가 없었다면 이주소로 이동
        } else {
            super.onAuthenticationSuccess(request, response, authentication);    //로그인 하기 전의 접속한 주소로 다시 돌아갑니다.
        }
    }

}
