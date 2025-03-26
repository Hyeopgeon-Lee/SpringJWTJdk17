package kopo.poly.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.dto.TokenDTO;
import kopo.poly.jwt.JwtStatus;
import kopo.poly.jwt.JwtTokenProvider;
import kopo.poly.jwt.JwtTokenType;
import kopo.poly.util.CmmUtil;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    // JWT 유틸 클래스
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * JWT 토큰을 기반으로 인증(Authentication) 객체를 생성하고,
     * Spring Security의 SecurityContext에 저장합니다.
     * <p>
     * 이 과정을 통해 Spring Security는 해당 요청을 인증된 사용자로 간주하며,
     * 이후 컨트롤러 또는 서비스에서 @AuthenticationPrincipal 등을 통해 사용자 정보를 활용할 수 있습니다.
     *
     * @param token 유효한 JWT Access Token 문자열
     */
    private void setAuthentication(String token) {
        Authentication authentication = jwtTokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * 기존의 Access Token을 저장한 쿠키를 삭제합니다.
     * <p>
     * 동일한 이름의 쿠키를 생성하고 maxAge를 0으로 설정하면 브라우저에서 해당 쿠키를 제거합니다.
     * 주로 Access Token 재발급 전 기존 토큰 제거 시 사용됩니다.
     *
     * @param response HTTP 응답 객체 (Set-Cookie 헤더 설정용)
     */
    private void clearCookieAccessToken(HttpServletResponse response) {
        ResponseCookie deleteCookie = ResponseCookie.from(accessTokenName, "")
                .path("/")
                .maxAge(0)
                .build();

        response.setHeader("Set-Cookie", deleteCookie.toString());
    }

    /**
     * 새로 생성된 Access Token을 쿠키에 저장합니다.
     * <p>
     * 클라이언트가 다음 요청부터 이 쿠키를 통해 자동 인증될 수 있도록 설정합니다.
     * 보안을 위해 httpOnly 설정을 통해 JS에서 쿠키 접근을 제한하며,
     * 도메인과 유효시간도 함께 설정합니다.
     *
     * @param response HTTP 응답 객체 (Set-Cookie 헤더 설정용)
     * @param token    새로 발급한 JWT Access Token 문자열
     */
    private void setCookieAccessToken(HttpServletResponse response, String token) {
        ResponseCookie newCookie = ResponseCookie.from(accessTokenName, token)
                .domain("localhost")     // 운영 환경에서는 실제 도메인으로 변경 필요
                .path("/")
                .httpOnly(true)
                .maxAge(accessTokenValidTime)
                .build();

        response.setHeader("Set-Cookie", newCookie.toString());
    }

    /**
     * Access Token이 만료된 경우 Refresh Token을 검사하여,
     * 유효하면 새로운 Access Token을 발급하고 인증을 재설정합니다.
     * <p>
     * Refresh Token이 만료되었거나 유효하지 않으면 재로그인이 필요합니다.
     *
     * @param request  HTTP 요청 객체
     * @param response HTTP 응답 객체
     */
    private void handleRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.REFRESH_TOKEN));
        JwtStatus refreshTokenStatus = jwtTokenProvider.validateToken(refreshToken);

        log.info("RefreshToken 상태 : {}", refreshTokenStatus);

        if (refreshTokenStatus.isValid()) {
            // RefreshToken으로부터 사용자 정보 추출
            TokenDTO dto = jwtTokenProvider.getTokenInfo(refreshToken);
            String userId = CmmUtil.nvl(dto.userId());
            String userRoles = CmmUtil.nvl(dto.role());

            log.info("RefreshToken 사용자 : {}, 권한 : {}", userId, userRoles);

            // AccessToken 재발급
            String newAccessToken = jwtTokenProvider.createToken(dto, JwtTokenType.ACCESS_TOKEN);

            // 기존 쿠키 제거 후 새 토큰으로 재설정
            clearCookieAccessToken(response);
            setCookieAccessToken(response, newAccessToken);

            // 인증 처리
            setAuthentication(newAccessToken);

        } else if (refreshTokenStatus.isExpired()) {
            log.info("Refresh Token 만료: 사용자 재로그인 필요");

        } else {
            log.info("Refresh Token 오류: 위조 가능성 있음");
        }
    }
    
    /**
     * JWT 인증 필터의 핵심 로직을 수행합니다.
     * <p>
     * 요청마다 실행되며, Access Token의 유효성을 먼저 검사하고,
     * 유효하지 않은 경우 Refresh Token을 확인하여 인증을 재설정합니다.
     * 인증이 완료되면 SecurityContext에 저장된 인증 정보로 요청이 처리됩니다.
     *
     * @param request     HTTP 요청 객체
     * @param response    HTTP 응답 객체
     * @param filterChain 필터 체인
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        log.info("{}.doFilterInternal Start!", this.getClass().getName());

        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.ACCESS_TOKEN));
        JwtStatus accessTokenStatus = jwtTokenProvider.validateToken(accessToken);

        log.info("AccessToken 상태 : {}", accessTokenStatus);

        if (accessTokenStatus.isValid()) {
            // AccessToken이 유효하면 인증 처리
            setAuthentication(accessToken);

        } else if (accessTokenStatus.isInvalid()) {
            // 만료 또는 거부된 토큰이면 Refresh Token 확인
            handleRefreshToken(request, response);
        }

        log.info("{}.doFilterInternal End!", this.getClass().getName());

        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }

    /**
     * JWT 인증 필터를 적용하지 않을 경로를 정의합니다.
     * <p>
     * 정적 리소스 요청(css, js 등), 로그인/회원가입 등은 JWT 필터를 건너뜁니다.
     * 경로는 단순히 포함(contain) 여부로 필터 제외를 판단합니다.
     *
     * @param request HTTP 요청 객체
     * @return true인 경우 해당 경로는 필터 제외 (인증 검사하지 않음)
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        log.info("{}.shouldNotFilter Start!", this.getClass().getName());

        String path = CmmUtil.nvl(request.getServletPath());

        // JWT 인증 제외 대상 목록
        List<String> excludedPaths = List.of(
                "/css/",               // 정적 CSS 파일
                "/js/",                // 정적 JS 파일
                "/html/index.html",    // 메인 페이지
                "/html/ss/",           // 서브 HTML 페이지
                "/login/v1/",          // 로그인 요청
                "/reg/v1",             // 회원가입 요청
                "/favicon.ico"         // 파비콘 요청
        );

        boolean excluded = excludedPaths.stream().anyMatch(path::contains);

        log.info("필터 제외 여부 : {} → {}", path, excluded);
        log.info("{}.shouldNotFilter End!", this.getClass().getName());

        return excluded; // true면 필터 미적용
    }
}
