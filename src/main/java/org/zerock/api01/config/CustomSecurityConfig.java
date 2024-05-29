package org.zerock.api01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.filter.RefreshTokenFilter;
import org.zerock.api01.security.filter.TokenCheckFilter;
import org.zerock.api01.security.handler.APILoginSuccessHandler;
import org.zerock.api01.util.JWTUtil;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Log4j2
public class CustomSecurityConfig {

    private final APIUserDetailsService apiUserDetailsService;
    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        // 암호화 설정
        return new BCryptPasswordEncoder();
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        log.info("--------------web configure---------------");
        // 정적 파일 요청 무시하는 설정
        return (web) -> web.ignoring().
                requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                .passwordEncoder(passwordEncoder());
        // 인증관리자 빌더를 통해 인증 관리자를 생성
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
        // http에 인증 관리자 설정
        http.authenticationManager(authenticationManager);
        // APILoginFilter 를 불러올때 사용할 URL 설정
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        // APILoginFilter 가 위에서 만든 인증 관리자를 사용할지 설정
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);

        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // APILoginFilter 전에 실행할 필터를 설정
        http.addFilterBefore(tokenCheckFilter(jwtUtil, apiUserDetailsService), UsernamePasswordAuthenticationFilter.class);
        // TokenCheckFilter 실행되기 전 RefreshTokenFilter 가 실행됨.
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken",jwtUtil), TokenCheckFilter.class);


        // csrf 설정 끄기
        http.csrf().disable();
        // 세션 생성 설정 끄기
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
        });
        return http.build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 모든 패턴을 허락
        // origin 의 의미 protocol+host+port
        // protocol : http://, https://
        // host : 도메인(localhost, www.naver.com, www.goole.com) 이나 ip 주소
        // post : :80, :8080, :3306
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        // ajax 에서 실행할 메서드 설정
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "HEAD"));
        // 사용할 헤더 설정
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type","Cache-Control"));
        // cors 설정을 사용 설정
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil, APIUserDetailsService apiUserDetailsService) {
        return new TokenCheckFilter(apiUserDetailsService, jwtUtil);
    }
}
