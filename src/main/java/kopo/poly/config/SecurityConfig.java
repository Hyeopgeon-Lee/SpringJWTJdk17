package kopo.poly.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security의 핵심 설정.
 * <p>
 * 목표
 * - 세션 완전 미사용(Stateless)
 * - 스프링 리소스 서버(OAuth2 Resource Server) + JWT 인증
 * - Access Token은 쿠키에서 먼저 읽고(커스텀 BearerTokenResolver), 없으면 Authorization 헤더 사용
 * - 정적 리소스/공개 API는 인증 없이 접근 허용
 * - 로그아웃 시 쿠키 정리
 * <p>
 * 구성 요약
 * - PasswordEncoder: 회원가입/비밀번호 변경 시 해시용
 * - AuthenticationManager: /login API에서 사용자 인증(UsernamePasswordAuthenticationToken)
 * - SecurityFilterChain: 인가 규칙, 리소스 서버(JWT), 세션/CSRF/CORS 등 보안 정책
 * <p>
 * 참고
 * - 리소스 서버의 JWT 검증기/권한변환기는 JwtConfig 에서 빈으로 제공(JwtDecoder, JwtAuthenticationConverter).
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /**
     * JWT → 권한(ROLE_*) 변환기. JwtConfig에서 roles(List<String>) 클레임을 권한으로 매핑하도록 구성됨
     */
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    /**
     * 커스텀 BearerTokenResolver. 쿠키(Access Token) → 헤더 순으로 토큰을 찾는다
     */
    private final BearerTokenResolver bearerTokenResolver;

    /**
     * Nimbus 기반 JWT 디코더(검증기). HS256 서명 검증/만료 검사 수행
     */
    private final JwtDecoder jwtDecoder;

    /**
     * 로그아웃 시 제거할 Access Token 쿠키명
     */
    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    /**
     * 로그아웃 시 제거할 Refresh Token 쿠키명
     */
    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    /**
     * 비밀번호 해시 함수(BCrypt).
     * - 회원가입/비번변경 시 사용.
     * - 인증 시 스프링 시큐리티가 사용자 저장 해시와 비교.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * AuthenticationManager 주입.
     * - LoginController에서 authenticationManager.authenticate(...) 호출 시 사용됨.
     * - 내부적으로 UserDetailsService + PasswordEncoder가 동작하여 사용자 인증을 수행.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * 보안 필터 체인.
     * - 여기서 모든 보안 정책(세션/CSRF/CORS/인가/JWT/로그아웃 등)을 정의한다.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                /* =======================
                   세션/CSRF/CORS 기본 정책
                   ======================= */
                // 세션을 절대 생성하지 않음(완전 Stateless)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CSRF: 폼 기반 세션 인증이 아니고, 쿠키-기반 JWT를 쓰되 SameSite/HttpOnly로 완화하므로 비활성화
                //  - 크로스 도메인 POST가 필요하고, SameSite=None을 쓰는 경우에는 CSRF 토큰 전략 추가 검토 권장
                .csrf(AbstractHttpConfigurer::disable)

                // CORS: 게이트웨이/프록시에서 처리하는 경우 꺼두지만,
                //  - 프런트가 다른 Origin에서 호출한다면 CorsConfigurationSource를 등록해
                //  http.cors(...).configurationSource(...) 로 활성화
                .cors(AbstractHttpConfigurer::disable)

                /* =======================
                   인가(Authorization) 규칙
                   ======================= */
                .authorizeHttpRequests(auth -> auth
                        // 정적 리소스/루트 문서 허용
                        //  - Spring Boot 기본 정적 위치(classpath:/static 등) 아래의 파일을 직접 서비스
                        //  - 아래 매칭은 /static/** 에 배치한 /css, /js, /favicon.ico, /html/** 등의 파일 접근 허용
                        .requestMatchers("/", "/index.html",
                                "/css/**", "/js/**",
                                "/favicon.ico",
                                "/html/**")
                        .permitAll()

                        // 공개 API: 회원가입/로그인/토큰 재발급 등은 누구나 접근 가능
                        .requestMatchers("/reg/**", "/login/v1/**", "/auth/**")
                        .permitAll()

                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                )

                /* =======================
                   리소스 서버(JWT 인증)
                   ======================= */
                .oauth2ResourceServer(oauth2 -> oauth2
                        // 요청에서 토큰을 찾는 규칙(쿠키 우선 → 헤더)
                        .bearerTokenResolver(bearerTokenResolver)

                        // JWT 검증기/권한 변환기 연결
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)
                        )
                )

                /* =======================
                   로그아웃 처리
                   ======================= */
                // - 서버 세션이 없으므로 주로 "쿠키 삭제"가 핵심
                // - 클라이언트 측 저장(예: localStorage) 토큰이 있다면 프런트에서도 별도 삭제 필요
                .logout(logout -> logout
                        .logoutUrl("/logout") // 호출 시 토큰 쿠키 제거
                        .deleteCookies(accessTokenName, refreshTokenName)
                );

        return http.build();
    }
}
