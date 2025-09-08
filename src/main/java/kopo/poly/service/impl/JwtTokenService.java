package kopo.poly.service.impl;

import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IJwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 발급(Access/Refresh) 및 쿠키 저장을 담당하는 구현체.
 * <p>
 * 설계 요점
 * - 인코딩은 Spring Security의 Nimbus 기반 JwtEncoder를 사용한다.
 * - HS256 대칭키 서명을 사용하며, 알고리즘 헤더를 명시한다.
 * - 클레임:
 * - sub       : userId
 * - username  : 사용자 표시 이름
 * - roles     : List<String> 권한 목록 (Resource Server에서 ROLE_ 접두사로 매핑)
 * - type      : "access" | "refresh" (토큰 용도 구분)
 * <p>
 * 보안 유의사항
 * - 토큰 클레임에는 개인식별정보(PII)를 과도하게 담지 않는다.
 * - Refresh 토큰은 재발급 시 같이 로테이트하는 정책을 권장한다.
 * - 쿠키는 HttpOnly, Secure을 기본으로 사용하고, SameSite는 환경에 맞게 설정한다.
 */
@Service
@RequiredArgsConstructor
public class JwtTokenService implements IJwtTokenService {

    // 토큰 클레임 키 및 값에 대한 상수 정의(오타 방지)
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    /**
     * Spring Security Nimbus 기반 인코더. JwtConfig에서 키로 초기화됨
     */
    private final JwtEncoder jwtEncoder;

    /**
     * iss(issuer) 클레임에 들어갈 발급자 식별자
     */
    @Value("${jwt.token.creator}")
    private String issuer;

    /**
     * Access Token TTL(초)
     */
    @Value("${jwt.token.access.valid.time}")
    private long accessTtlSec;

    /**
     * Refresh Token TTL(초)
     */
    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTtlSec;

    /**
     * Access Token을 담는 쿠키 이름
     */
    @Value("${jwt.token.access.name}")
    private String accessCookie;

    /**
     * Refresh Token을 담는 쿠키 이름
     */
    @Value("${jwt.token.refresh.name}")
    private String refreshCookie;

    /**
     * 공통 인코딩 로직.
     * - 토큰 유효기간, 타입(access/refresh)만 다르게 설정하여 재사용한다.
     */
    private String encode(UserInfoDTO user, long ttlSec, String type) {
        Instant now = Instant.now();                  // UTC 기준
        List<String> roles = splitRoles(user.roles()); // "USER,ADMIN" → ["USER","ADMIN"]

        // 클레임 구성
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)                       // iss
                .issuedAt(now)                        // iat
                .expiresAt(now.plusSeconds(ttlSec))   // exp
                .subject(user.userId())               // sub = userId
                .claim(CLAIM_USERNAME, user.userName())
                .claim(CLAIM_TYPE, type)
                .claim(CLAIM_ROLES, roles)            // 권한 목록(List<String>)
                .build();

        // HS256 헤더 명시
        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();

        // 인코딩(서명 포함)
        return jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
    }

    /**
     * 권한 문자열(ROLE_ADMIN, ROLE_USER)을 List<String>으로 변환.
     * 값이 비어있으면 기본값으로 "USER" 부여.
     */
    private static List<String> splitRoles(String roles) {
        if (roles == null || roles.isBlank()) return List.of("USER");
        return Arrays.stream(roles.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    /**
     * Access Token 생성.
     *
     * @param user 토큰에 반영할 최소 사용자 정보(특히 userId 필수)
     * @return 서명된 JWT 문자열
     */
    @Override
    public String generateAccessToken(UserInfoDTO user) {
        return encode(user, accessTtlSec, TYPE_ACCESS);
    }

    /**
     * Refresh Token 생성.
     *
     * @param user 토큰에 반영할 최소 사용자 정보(특히 userId 필수)
     * @return 서명된 JWT 문자열
     */
    @Override
    public String generateRefreshToken(UserInfoDTO user) {
        return encode(user, refreshTtlSec, TYPE_REFRESH);
    }

    /**
     * Access/Refresh 토큰을 각각 HttpOnly 쿠키로 저장한다.
     * <p>
     * 쿠키 속성 기본값
     * - httpOnly: true  (JS에서 접근 불가)
     * - secure  : true  (HTTPS에서만 전송)
     * - path    : "/"   (전역 경로)
     * - sameSite: "Lax" (크로스 사이트 폼 POST가 필요한 경우 None + Secure 조합 고려)
     * - maxAge  : 토큰 TTL과 동일
     * <p>
     * 주의
     * - 프런트가 다른 도메인/서브도메인일 경우 Domain 설정이 필요할 수 있음.
     * - 프록시/게이트웨이가 있는 경우, 실제 배포 환경에 맞춰 Secure, SameSite, Domain을 점검할 것.
     */
    @Override
    public void writeTokensAsCookies(HttpServletResponse res, String accessToken, String refreshToken) {
        ResponseCookie at = ResponseCookie.from(accessCookie, accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Lax")
                .maxAge(accessTtlSec)
                .build();

        ResponseCookie rt = ResponseCookie.from(refreshCookie, refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Lax")
                .maxAge(refreshTtlSec)
                .build();

        // Set-Cookie 헤더는 여러 번 추가 가능하므로 각각 추가
        res.addHeader("Set-Cookie", at.toString());
        res.addHeader("Set-Cookie", rt.toString());
    }
}
