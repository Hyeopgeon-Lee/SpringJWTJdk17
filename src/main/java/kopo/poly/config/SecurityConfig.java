package kopo.poly.config;

import kopo.poly.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    // JWT 검증을 위한 필터
    // 초기 Spring Filter를 Spring에 제어가 불가능했지만, 현재 제어 가능함
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info(this.getClass().getName() + ".PasswordEncoder Start!");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        log.info(this.getClass().getName() + ".filterChain Start!");

        http.csrf(AbstractHttpConfigurer::disable)         // POST 방식 전송을 위해 csrf 막기
                .authorizeHttpRequests(authz -> authz // 페이지 접속 권한 설정
                                .requestMatchers("/notice/v1/**").hasAnyAuthority("ROLE_USER") // USER 권한
                                .requestMatchers("/user/v1/**").authenticated() // Spring Security 인증된 사용자만 접근
                                .requestMatchers("/html/user/**").authenticated() // Spring Security 인증된 사용자만 접근

                                .requestMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN") // 관리자 권한
//                        .anyRequest().authenticated() // 그외 나머지 url 요청은 인증된 사용자만 가능
                                .anyRequest().permitAll() // 그 외 나머지 url 요청은 인증 받지 않아도 접속 가능함
                )
                .formLogin(login -> login // 로그인 페이지 설정
                        .loginPage("/html/ss/login.html")
                        .loginProcessingUrl("/login/v1/loginProc")
                        .usernameParameter("userId") // 로그인 ID로 사용할 html의 input객체의 name 값
                        .passwordParameter("password") // 로그인 패스워드로 사용할 html의 input객체의 name 값
                        .successForwardUrl("/login/v1/loginSuccess") // Web MVC, Controller 사용할 때 적용 / 로그인 성공 URL
                        .failureForwardUrl("/login/v1/loginFail") // Web MVC, Controller 사용할 때 적용 / 로그인 실패 URL
                )
                .logout(logout -> logout
                        .logoutUrl("/user/v1/logout") // 로그이웃 요청 URL
                        .clearAuthentication(true) // Spring Security 저장된 인증 정보 초기화
                        .deleteCookies(accessTokenName, refreshTokenName) // JWT 토큰 삭제
                        .logoutSuccessUrl("/html/index.html") // 로그아웃 성공 처리 URL(세션 값 삭제)
                )
                // Spring Security의 UsernamePasswordAuthenticationFilter가 실행되지 전에
                // 내가 만든 JwtAuthenticationFilter 필터가 실행되도록 설정함
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)

                // 세션 사용하지 않도록 설정함
                .sessionManagement(ss -> ss.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        ;

        return http.build();
    }
}
