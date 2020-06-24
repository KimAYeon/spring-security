package net.cj.ethics.admin.common.security;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.util.Collection;

public class CustomAccessDecisionVoter implements AccessDecisionVoter<FilterInvocation> {
    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return false;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass != null && aClass.isAssignableFrom(FilterInvocation.class);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation filterInvocation, Collection<ConfigAttribute> collection) {
        assert authentication != null;
        assert filterInvocation != null;
        assert collection != null;

        SecurityConfig securityConfig = null;
        boolean containAuthority = false;
        for(final ConfigAttribute configAttribute : collection) {
            if(configAttribute instanceof SecurityConfig) {
                securityConfig = (SecurityConfig) configAttribute;
                for(GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                    containAuthority = securityConfig.getAttribute().equals(grantedAuthority.getAuthority());
                    if(containAuthority) { break; }
                } if(containAuthority) { break; }
            }
        }

        return containAuthority ? ACCESS_GRANTED : ACCESS_DENIED;
    }
}
