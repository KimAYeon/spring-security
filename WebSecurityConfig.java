package net.cj.ethics.admin.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.BeanDefinitionDsl;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 스프링 시큐리티가 사용자를 인증하는 방법이 담긴 객체.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    /**
     * 스프링 시큐리티 룰을 무시하게 하는 Url 규칙.
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/resources/**")
                .antMatchers("/webjars/**")
                .antMatchers("/error/**")
                .antMatchers("/favicon.ico/**");
    }

    /**
     * 스프링 시큐리티 룰.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                    .antMatchers("/main").authenticated()
//                    .antMatchers("/sample/sampleValidation").hasRole("USER")
                    .antMatchers("/sample/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/sample/sampleLogin")
                .loginProcessingUrl("/login")
                .successHandler(loginSuccessHandler())
            .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
            .and()
                .csrf()
                .disable()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .authenticationEntryPoint(authenticationEntryPoint())
             .and()
                .addFilterAfter(filterSecurityInterceptor(), FilterSecurityInterceptor.class)
//        .and().sessionManagement()
//              .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    ;
}

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        AuthenticationProvider authenticationProvider = new CustomAuthenticationProvider(userDetailsService());
        return authenticationProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler();
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint();
    }

    /**
     * FMS API 권한 Filter.
     * @return securityMetadataSource() 가 적용된 데이터.
     * @throws Exception
     */
    @Bean
    public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(filterInvocationSecurityMetadataSource());
        filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        return filterSecurityInterceptor;
    }
    //여러 Voter를 추가하는 것이 가능. List로 index가 작은 Voter가 먼저 투표. 투표 포기(ACCESS_ABSTAIN)
    // 가 되는 경우, 다음 Voter에게 넘어감.
    @Bean
    public AffirmativeBased affirmativeBased() {
        CustomAccessDecisionVoter voter = new CustomAccessDecisionVoter();
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        voters.add(voter);
        return new AffirmativeBased(voters);
    }

    @Bean
    public FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource() {
        return new CustomFilterSecurityMetadataSource();
    }

}
