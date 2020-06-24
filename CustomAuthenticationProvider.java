package net.cj.ethics.admin.common.security;

import lombok.Setter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Setter
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        System.out.println(username);
        System.out.println(password);

//        Uses user = null;
//
//        if(!StringUtils.isEmpty(username)) {
//            user = (User) userDetailsService.loadUserByUsername(username);
//        }

        // 비밀번호가 일치하지 않는 경우
//        if(user.getPassword().equals(password)) {
//            throw new BadCredentialsException("Bad credential");
//        }
//
//        ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
//        auth.add(new SimpleGrantedAuthority(user.getAuthority()));

        ArrayList<GrantedAuthority> auth = new ArrayList<GrantedAuthority>();
        auth.add(new SimpleGrantedAuthority("ROLE_USER"));
        User user = new User(username, password, auth);
        return new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
