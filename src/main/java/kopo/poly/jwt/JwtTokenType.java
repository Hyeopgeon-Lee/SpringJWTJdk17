package kopo.poly.jwt;

/**
 * JWT 토큰의 종류를 구분하는 열거형(enum) 클래스입니다.
 * <p>
 * - ACCESS_TOKEN : 로그인 후 사용자의 인증 및 권한 처리를 위한 짧은 생명 주기의 토큰
 * - REFRESH_TOKEN : Access Token이 만료되었을 때 새로운 Access Token을 발급받기 위한 토큰
 * <p>
 * 이 enum은 JWT 필터나 토큰 처리 메서드에서 어떤 토큰을 다루는지를 명확히 구분하기 위해 사용됩니다.
 */
public enum JwtTokenType {
    ACCESS_TOKEN,   // 사용자 인증에 사용하는 토큰
    REFRESH_TOKEN   // Access Token 재발급용 토큰
}
