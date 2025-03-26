package kopo.poly.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import kopo.poly.dto.TokenDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // JWT 서명에 사용할 비밀 키 (Base64 인코딩된 문자열)
    @Value("${jwt.secret.key}")
    private String secretKey;

    // JWT 발급자 정보
    @Value("${jwt.token.creator}")
    private String creator;

    // Access Token 유효 시간 (초)
    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    // Access Token 쿠키 이름
    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    // Refresh Token 유효 시간 (초)
    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    // Refresh Token 쿠키 이름
    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    /**
     * 사용자 정보를 기반으로 JWT 토큰을 생성합니다.
     * <p>
     * 이 메서드는 사용자 ID, 이름, 권한 정보를 담고 있는 {@link TokenDTO} 객체와
     * 생성할 토큰 타입(ACCESS 또는 REFRESH)을 기반으로 JWT를 생성합니다.
     * <p>
     * 내부적으로 JWT의 Payload에 사용자 ID(subject), 이름(userName), 권한(roles)을 클레임으로 저장하며,
     * 서명은 HS256 알고리즘을 사용하여 SecretKey로 암호화합니다.
     * <p>
     * 토큰 유효 기간은 토큰 유형에 따라 설정됩니다:
     * - ACCESS_TOKEN: 짧은 시간 유효, 사용자 인증 시 사용
     * - REFRESH_TOKEN: 긴 시간 유효, Access Token 재발급 시 사용
     *
     * @param dto          사용자 정보를 담은 TokenDTO (userId, userName, role)
     * @param jwtTokenType 생성할 토큰의 유형 (ACCESS_TOKEN 또는 REFRESH_TOKEN)
     * @return 생성된 JWT 문자열 (암호화된 서명 포함)
     */
    public String createToken(TokenDTO dto, JwtTokenType jwtTokenType) {
        log.info("{}.createToken Start!", getClass().getName());

        // 토큰 유형에 따라 유효 시간 설정 (초 단위)
        long validTime = (jwtTokenType == JwtTokenType.ACCESS_TOKEN) ? accessTokenValidTime : refreshTokenValidTime;

        // JWT의 payload에 저장할 클레임 정의
        Claims claims = Jwts.claims()
                .setIssuer(creator)                     // 발급자
                .setSubject(dto.userId());              // 사용자 ID (subject)
        claims.put("userName", dto.userName());         // 사용자 이름
        claims.put("roles", dto.role());               // 사용자 권한 (ROLE_USER 등)

        // 현재 시간 기준으로 발급 시간과 만료 시간 설정
        Date now = new Date();
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // JWT 생성 및 반환
        return Jwts.builder()
                .setClaims(claims)                      // 사용자 정보 포함
                .setIssuedAt(now)                       // 발급 시간
                .setExpiration(new Date(now.getTime() + validTime * 1000)) // 만료 시간
                .signWith(secret, SignatureAlgorithm.HS256)                // 서명 알고리즘 및 키
                .compact();                             // JWT 문자열 생성
    }

    /**
     * JWT 토큰을 파싱하여 사용자 정보를 추출합니다.
     * <p>
     * 이 메서드는 전달받은 JWT 토큰 문자열을 복호화하여 내부의 Claims 정보를 추출하고,
     * 해당 토큰에 포함된 사용자 ID(subject), 이름(userName), 권한 정보(roles)를 가져옵니다.
     * 추출된 정보를 기반으로 TokenDTO 객체를 생성하여 반환합니다.
     * <p>
     * 이 메서드는 사용자 인증 이후 토큰에서 사용자 세부 정보를 확인할 때 주로 사용됩니다.
     *
     * @param token JWT 문자열 (Access Token 또는 Refresh Token)
     * @return TokenDTO 객체 (userId, userName, role 포함)
     */
    public TokenDTO getTokenInfo(String token) {
        log.info("{}.getTokenInfo Start!", getClass().getName());

        // JWT 서명을 위한 비밀키 생성
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // 토큰 파싱 및 Claims 추출
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // 클레임에서 사용자 정보 추출
        String userId = CmmUtil.nvl(claims.getSubject()); // subject는 userId로 사용
        String userName = CmmUtil.nvl((String) claims.get("userName"));
        String role = CmmUtil.nvl((String) claims.get("roles"));

        log.info("userId: {}, userName: {}, role: {}", userId, userName, role);
        log.info("{}.getTokenInfo End!", getClass().getName());

        // 사용자 정보를 담은 TokenDTO 객체 생성 및 반환
        return TokenDTO.builder()
                .userId(userId)
                .userName(userName)
                .role(role)
                .build();
    }

    /**
     * JWT 토큰을 기반으로 Spring Security의 인증(Authentication) 객체를 생성합니다.
     * <p>
     * 이 메서드는 JWT 내부에 포함된 사용자 ID와 권한(roles) 정보를 추출하여,
     * Spring Security에서 사용할 수 있는 {@link UsernamePasswordAuthenticationToken} 객체로 변환합니다.
     * JWT 기반 인증 방식에서는 비밀번호는 사용하지 않으므로 빈 문자열로 처리합니다.
     * <p>
     * 이 메서드는 JwtAuthenticationFilter 또는 인증이 필요한 보안 필터 체인에서
     * SecurityContext에 인증 객체를 주입할 때 사용됩니다.
     *
     * @param token JWT 문자열 (Access Token)
     * @return 인증된 사용자 정보를 담은 Authentication 객체
     */
    public Authentication getAuthentication(String token) {
        log.info("{}.getAuthentication Start!", getClass().getName());

        // 토큰에서 사용자 정보 추출 (userId, role)
        TokenDTO dto = getTokenInfo(token);
        String userId = CmmUtil.nvl(dto.userId());
        String roles = CmmUtil.nvl(dto.role());

        // 문자열로 되어 있는 권한 목록(예: ROLE_USER,ROLE_ADMIN 등)을 Set<GrantedAuthority>로 변환
        Set<GrantedAuthority> authorities = new HashSet<>();
        if (!roles.isEmpty()) {
            Arrays.stream(roles.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .forEach(authorities::add);
        }

        log.info("userId: {}, roles: {}", userId, roles);
        log.info("{}.getAuthentication End!", getClass().getName());

        // Spring Security 인증 객체 생성 및 반환
        return new UsernamePasswordAuthenticationToken(userId, "", authorities);
    }

    /**
     * HTTP 요청 객체에서 쿠키를 통해 JWT 토큰 값을 추출하는 메서드입니다.
     * <p>
     * 클라이언트가 요청 시 함께 전송한 쿠키 목록 중에서, 전달된 토큰 유형(ACCESS 또는 REFRESH)에 따라
     * 해당 이름을 가진 쿠키 값을 찾아 반환합니다. 쿠키가 존재하지 않거나 해당 토큰 이름이 없으면 빈 문자열을 반환합니다.
     * <p>
     * 이 메서드는 인증 필터나 사용자 인증 정보 확인 시 사용됩니다.
     *
     * @param request   클라이언트의 HTTP 요청 객체
     * @param tokenType 조회하려는 JWT 토큰 유형 (ACCESS_TOKEN 또는 REFRESH_TOKEN)
     * @return 해당 토큰 이름의 쿠키 값, 없을 경우 빈 문자열 반환
     */
    public String resolveToken(HttpServletRequest request, JwtTokenType tokenType) {
        log.info("{}.resolveToken Start!", getClass().getName());

        // 토큰 유형에 따라 쿠키 이름 결정
        String tokenName = (tokenType == JwtTokenType.ACCESS_TOKEN) ? accessTokenName :
                (tokenType == JwtTokenType.REFRESH_TOKEN) ? refreshTokenName : "";

        // 요청에 쿠키가 없다면 빈 문자열 반환
        if (request.getCookies() == null) return "";

        // 해당 이름을 가진 쿠키 값을 찾아 반환, 없으면 빈 문자열
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(tokenName))
                .findAny()
                .map(Cookie::getValue)
                .orElse("");
    }


    /**
     * JWT 토큰의 유효성을 검증하는 메서드입니다.
     * <p>
     * - 전달받은 JWT 문자열이 비어 있거나 파싱 과정에서 예외가 발생하면 DENIED 상태를 반환합니다.<br>
     * - 정상적으로 파싱된 경우 토큰의 만료 시간을 현재 시간과 비교하여 만료 여부를 판단합니다.<br>
     * - 만료된 토큰은 EXPIRED, 유효한 토큰은 ACCESS 상태를 반환합니다.
     * <p>
     * 이 메서드는 JWT 인증 필터 또는 토큰 재발급 로직에서 토큰 상태 확인 용도로 사용됩니다.
     *
     * @param token JWT 문자열 (Access 또는 Refresh Token)
     * @return JwtStatus - ACCESS (정상), EXPIRED (만료), DENIED (유효하지 않거나 파싱 오류)
     */
    public JwtStatus validateToken(String token) {
        if (token.isEmpty()) return JwtStatus.DENIED;

        try {
            // 비밀키를 기반으로 서명 검증 준비
            SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

            // 토큰 파싱 및 클레임 추출
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // 현재 시간과 만료 시간 비교
            return claims.getExpiration().before(new Date()) ? JwtStatus.EXPIRED : JwtStatus.ACCESS;

        } catch (ExpiredJwtException e) {
            // 명시적으로 만료된 경우 (파싱은 성공했지만 시간 초과)
            return JwtStatus.EXPIRED;

        } catch (JwtException | IllegalArgumentException e) {
            // 서명 위조, 구조 손상, null 전달 등 유효하지 않은 토큰
            return JwtStatus.DENIED;
        }
    }

}