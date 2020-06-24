package net.cj.ethics.admin.common.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

public class CustomFilterSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        HttpServletRequest request = ((FilterInvocation) o).getRequest();
        String httpMethod = request.getMethod().toUpperCase();
        String url = request.getRequestURI();
        String key = String.format("%s %s", httpMethod, url);

        if(!url.startsWith("/api")) {
            return null;
        } else {
            String[] roles = null;

            if(key.equals("GET /api/sample/user")) {
                roles = new String[] {"ROLE_ADMIN", "ROLE_USER"};
            }
            if(key.equals("GET /api/sample/admin")) {
                roles = new String[] {"ROLE_ADMIN"};
            }

            return SecurityConfig.createList(roles);
        }
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}
