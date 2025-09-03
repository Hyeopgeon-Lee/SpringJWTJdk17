package kopo.poly.service;

import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.dto.UserInfoDTO;

/**
 * JWT 발급 및 쿠키 저장과 관련된 작업을 정의하는 서비스 인터페이스.
 * <p>
 * 설계 목적
 * - 컨트롤러는 구체 구현체에 의존하지 않고, 이 인터페이스에만 의존한다.
 * - 토큰 발급(Access/Refresh)과 쿠키 저장을 한 곳에서 관리해, 발급·보관 정책을 일관되게 유지한다.
 * <p>
 * 토큰/클레임 정책(기본 가정)
 * - Access Token: 짧은 TTL, 리소스 서버 인증용
 * - Refresh Token: 긴 TTL, 재발급 엔드포인트(/auth/refresh)에서 Access Token 재발급용
 * - 공통 클레임 예시:
 * - sub: userId
 * - username: 사용자 표시 이름
 * - roles: List<String> 권한 목록 (리소스 서버에서 ROLE_*로 매핑)
 * - type: "access" | "refresh" (토큰 용도 구분)
 * <p>
 * 쿠키 정책(기본 가정)
 * - HttpOnly + Secure(+ SameSite=Lax 또는 None) 사용
 * - Path="/"
 * - 운영 환경에 따라 Domain, SameSite 조정 필요
 * <p>
 * 스레드-세이프티
 * - 구현체는 무상태(stateless)로 설계하는 것을 권장
 * - 키/TTL/쿠키명 등 설정은 외부 설정(application.yaml)에서 주입
 */
public interface IJwtTokenService {

    /**
     * Access Token을 생성한다.
     * <p>
     * 전형적 용도
     * - 로그인 성공 시, 혹은 /auth/refresh에서 재발급 시 사용
     * <p>
     * 요구 사항
     * - user.userId()는 sub 클레임으로 사용
     * - user.userName(), user.roles() 등은 필요 시 커스텀 클레임으로 포함
     *
     * @param user 토큰에 반영할 최소 사용자 정보(userId는 필수)
     * @return 생성된 Access Token 문자열(서명 포함, null/빈 문자열 금지)
     * @throws IllegalStateException 키/설정 오류 등으로 인코딩 실패 시
     */
    String generateAccessToken(UserInfoDTO user);

    /**
     * Refresh Token을 생성한다.
     * <p>
     * 전형적 용도
     * - 로그인 성공 시 함께 발급
     * - 보안 정책상 재발급 시 RT를 함께 로테이트(교체)하는 것을 권장
     * <p>
     * 요구 사항
     * - type 클레임에 "refresh"를 명시하여 용도 구분
     *
     * @param user 토큰에 반영할 최소 사용자 정보(userId는 필수)
     * @return 생성된 Refresh Token 문자열(서명 포함, null/빈 문자열 금지)
     * @throws IllegalStateException 키/설정 오류 등으로 인코딩 실패 시
     */
    String generateRefreshToken(UserInfoDTO user);

    /**
     * 두 토큰을 HttpOnly 쿠키로 저장한다.
     * <p>
     * 표준 동작(권장 예시)
     * - Access Token: HttpOnly, Secure, SameSite=Lax(or None), Path="/", Max-Age=accessTTL
     * - Refresh Token: HttpOnly, Secure, SameSite=Lax(or None), Path="/", Max-Age=refreshTTL
     * <p>
     * 유의 사항
     * - 크로스 도메인 환경에서는 SameSite=None + Secure 조합이 필수
     * - 게이트웨이/프록시가 있다면 Domain 설정을 검토
     *
     * @param res          응답 객체(Set-Cookie 헤더 추가)
     * @param accessToken  발급된 Access Token(필수)
     * @param refreshToken 발급된 Refresh Token(필수)
     */
    void writeTokensAsCookies(HttpServletResponse res, String accessToken, String refreshToken);

    /**
     * 편의 메서드: Access/Refresh 토큰을 모두 발급하고, 곧바로 쿠키로 저장한다.
     * <p>
     * 사용 시나리오
     * - 로그인 성공 처리 직후
     * - /auth/refresh에서 토큰 재발급 시(보안상 RT도 함께 로테이트하는 정책일 때)
     * <p>
     * 트랜잭션/에러
     * - 토큰 생성 중 오류 발생 시 IllegalStateException 등 런타임 예외가 전파될 수 있음
     * - 컨트롤러에서는 전역 예외 처리기(@RestControllerAdvice)로 일괄 응답 처리 권장
     *
     * @param user 토큰에 반영할 최소 사용자 정보(userId는 필수)
     * @param res  응답 객체(Set-Cookie 헤더 추가)
     */
    default void issueTokens(UserInfoDTO user, HttpServletResponse res) {
        String at = generateAccessToken(user);
        String rt = generateRefreshToken(user);
        writeTokensAsCookies(res, at, rt);
    }

}
