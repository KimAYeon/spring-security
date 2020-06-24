package net.cj.ethics.admin.common.security;

import lombok.Setter;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Setter
public class UserDetailsServiceImpl implements UserDetailsService {

    private String cjwIdDecryptKey;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        // 로그인 계정 DB 조회
//        User user = userService.selectDetailById(userId);

        // 조회된 사용자가 없을 경우
//        if(ObjectUtils.isEmpty(user)) {
//            throw new UsernameNotFoundException("Invalid username");
//        }

        return null;
    }
}
