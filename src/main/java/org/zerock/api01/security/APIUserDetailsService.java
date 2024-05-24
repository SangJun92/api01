package org.zerock.api01.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.zerock.api01.domain.APIUser;
import org.zerock.api01.dto.APIUserDTO;
import org.zerock.api01.repository.APIUserRepository;

import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class APIUserDetailsService implements UserDetailsService {

    //주입
    private final APIUserRepository apiUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 데이터베이스에 계정 확인
        Optional<APIUser> result = apiUserRepository.findById(username);

        // 에러 발생시 예외처리
        APIUser apiUser = result.orElseThrow(() -> new UsernameNotFoundException(username));

        log.info("APIUserDetailsService apiUser-----------------------------------");

        // 에러가 없다면 APIUserDTO를 생성하고 권한은 ROLE_USER로 설정
        APIUserDTO dto = new APIUserDTO(
                apiUser.getMid(),
                apiUser.getMpw(),
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

                log.info(dto);
                
        //생성된 APIUserDTO 반환        
        return dto;
    }
}
