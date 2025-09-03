package kopo.poly.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

/**
 * Bearer 토큰 추출기 구현체.
 * <p>
 * 목적
 * 1) HttpOnly 쿠키(Access Token)를 최우선으로 읽고
 * 2) 쿠키에 없을 때만 표준 Authorization 헤더(Bearer ...)를 사용한다.
 * <p>
 * 보안 정책
 * - URL 쿼리스트링이나 form 파라미터로 전달되는 토큰은 허용하지 않는다.
 * - 토큰 값은 로깅 금지. 유출 위험이 있으므로 여기에서는 어떠한 로깅도 하지 않는다.
 * <p>
 * 스레드-세이프티
 * - 상태를 가지지 않는 불변 객체로 설계되었고, Spring Bean으로 싱글턴 등록해도 안전하다.
 */
public class CookieOrHeaderBearerTokenResolver implements BearerTokenResolver {

    /**
     * Access Token이 저장된 쿠키 이름 (예: jwtAcccessToken)
     */
    private final String cookieName;

    /**
     * 표준 구현체에 위임하여 Authorization 헤더에서 Bearer 토큰을 파싱한다.
     * - 쿼리스트링/폼 파라미터는 보안상 비활성화한다.
     */
    private final DefaultBearerTokenResolver delegate;

    /**
     * @param cookieName 우선 조회할 쿠키 이름
     */
    public CookieOrHeaderBearerTokenResolver(String cookieName) {
        this.cookieName = cookieName;

        this.delegate = new DefaultBearerTokenResolver();
        // 보안상 허용하지 않음: URL 파라미터 또는 폼 파라미터로 토큰 전달
        this.delegate.setAllowFormEncodedBodyParameter(false);
        this.delegate.setAllowUriQueryParameter(false);
        // 필요 시 헤더의 "Bearer" 접두사 대소문자 허용 옵션 등을 조정할 수 있다(기본값 유지).
    }

    /**
     * 요청에서 Bearer 토큰을 하나 추출한다.
     * 1) 지정된 쿠키에서 토큰을 찾는다.
     * 2) 없거나 비어 있으면 Authorization 헤더의 Bearer 스킴을 파싱한다.
     */
    @Override
    public String resolve(HttpServletRequest request) {
        // 1) 쿠키 우선
        String fromCookie = extractFromCookie(request);
        if (fromCookie != null && !fromCookie.isEmpty()) {
            return fromCookie;
        }

        // 2) 표준 헤더 파서에 위임 (Authorization: Bearer xxx)
        return delegate.resolve(request);
    }

    /**
     * 쿠키에서 토큰 값을 찾아 반환한다.
     * - 값이 "Bearer xxx" 형태로 저장된 경우 접두사를 제거한다.
     * - 앞뒤 공백, 따옴표 등을 방어적으로 제거한다.
     */
    private String extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName())) {
                String v = c.getValue();
                if (v == null) return null;

                // 공백 제거 및 간단한 정규화
                v = v.trim();
                if (v.isEmpty()) return null;

                // 일부 프록시/클라이언트가 값에 따옴표를 둘러싸는 경우 방지
                if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
                    v = v.substring(1, v.length() - 1).trim();
                }

                // 혹시 "Bearer ..." 형태로 저장했다면 접두사 제거 (대소문자 무시)
                final String BEARER_PREFIX = "bearer ";
                if (v.length() > BEARER_PREFIX.length()
                        && v.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                    v = v.substring(BEARER_PREFIX.length()).trim();
                }

                return v.isEmpty() ? null : v;
            }
        }
        return null;
    }
}
