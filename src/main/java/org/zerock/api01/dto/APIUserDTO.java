package org.zerock.api01.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.zerock.api01.domain.APIUser;

import java.util.Collection;

@Getter
@Setter
@ToString
public class APIUserDTO extends User {

    private String mid;
    private String mpw;

    // APIUserDTO 생성자 UserDetails에 아이디, 패스워드 생성
    public APIUserDTO(String username, String password, Collection<GrantedAuthority> authorities) {

        super(username, password, authorities);
        this.mid = username;
        this.mpw = password;
    }
}
