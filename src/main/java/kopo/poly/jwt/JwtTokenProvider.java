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
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.token.creator}")
    private String creator;

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    /**
     * JWT 토큰(Access Token)생성
     *
     * @param dto 회원아이디, 회원이름, 권한, 토큰 타입
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public String createToken(TokenDTO dto, JwtTokenType jwtTokenType) {

        log.info(this.getClass().getName() + ".createToken Start!");

        long validTime = 0;

        if (jwtTokenType == JwtTokenType.ACCESS_TOKEN) { // Access Token이라면
            validTime = (accessTokenValidTime);

        } else if (jwtTokenType == JwtTokenType.REFRESH_TOKEN) { // Refresh Token이라면
            validTime = (refreshTokenValidTime);

        }

        Claims claims = Jwts.claims()
                .setIssuer(creator) // JWT 토큰 생성자 기입함
                .setSubject(dto.userId()); // 회원아이디 저장 : PK 저장(userId)

        claims.put("userName", dto.userName()); // JWT Paylaod에 정의된 기본 옵션 외 정보를 추가 - 사용자 이름 추가
        claims.put("roles", dto.role()); // JWT Paylaod에 정의된 기본 옵션 외 정보를 추가 - 사용자 권한 추가
        Date now = new Date();

        // 보안키 문자들을 JWT Key 형태로 변경하기
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // Builder를 통해 토큰 생성
        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now) // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + (validTime * 1000))) // set Expire Time
                .signWith(secret, SignatureAlgorithm.HS256)  // 사용할 암호화 알고리즘과
                .compact();

    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에 저장된 값 가져오기
     *
     * @param token 토큰
     * @return 회원 아이디(ex. hglee67)
     */
    public TokenDTO getTokenInfo(String token) {

        log.info(this.getClass().getName() + ".getTokenInfo Start!");

        // 보안키 문자들을 JWT Key 형태로 변경하기
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // JWT 토큰 정보
        Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();

        String userId = CmmUtil.nvl(claims.getSubject());
        String role = CmmUtil.nvl((String) claims.get("roles")); // LoginService 생성된 토큰의 권한명과 동일

        log.info("userId : " + userId);
        log.info("role : " + role);

        // TokenDTO는 자바17의 Record 객체 사용했기에 빌더패턴 적용함
        TokenDTO rDTO = TokenDTO.builder().userId(userId).role(role).build();

        log.info(this.getClass().getName() + ".getTokenInfo End!");

        return rDTO;
    }

    /**
     * Access Token의 userId, roles 가져옴
     * userId와 roles 값을 Spring Security 인증되었다고 Spring Security 인증 토큰 생성
     * JWT 토큰은 로그인 되었기에 생성됨
     * 즉, JWT 토큰이 있으면, 로그인이 된 상태
     *
     * @param token 토큰
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public Authentication getAuthentication(String token) {

        log.info(this.getClass().getName() + ".getAuthentication Start!");
        log.info("getAuthentication : " + token);

        TokenDTO rDTO = getTokenInfo(token); // 토큰에 저장된 정보 가져오기

        // JWT 토큰에 저장된 사용자 아이디 : hglee67
        String userId = CmmUtil.nvl(rDTO.userId());

        // JWT 토큰에 저장된 사용자 아이디 : ROLE_USER
        String roles = CmmUtil.nvl(rDTO.role());

        log.info("user_id : " + userId);
        log.info("roles : " + roles);

        Set<GrantedAuthority> pSet = new HashSet<>();
        if (!roles.isEmpty()) { //DB에 저장된 Role이 있는 경우에만 실행
            for (String role : roles.split(",")) {
                pSet.add(new SimpleGrantedAuthority(role));

            }
        }

        log.info(this.getClass().getName() + ".getAuthentication End!");

        // Spring Security가 로그인 성공된 정보를 Spring Security에서 사용하기 위해
        // Spring Security용 UsernamePasswordAuthenticationToken 생성
        return new UsernamePasswordAuthenticationToken(userId, "", pSet);
    }

    /**
     * 쿠기에 저장 및 HTTP 인증 헤더에 저장된 JWT 토큰(Access Token, Refresh Token) 가져오기
     * 쿠키 : Access Token, Refresh Token 저장됨
     * HTTP 인증 헤더 : Bearer 토큰으로 Access Token만 저장됨
     *
     * @param request   request 정보
     * @param tokenType token 유형
     * @return 쿠기에 저장된 토큰 값
     */
    public String resolveToken(HttpServletRequest request, JwtTokenType tokenType) {

        log.info(this.getClass().getName() + ".resolveToken Start!");

        AtomicReference<String> token = new AtomicReference<>(""); // 토큰
        String tokenName;

        if (tokenType == JwtTokenType.ACCESS_TOKEN) { // Access Token이라면
            tokenName = accessTokenName;

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) { // Refresh Token이라면
            tokenName = refreshTokenName;

        } else {
            tokenName = "";
        }

        // 쿠키에 존재하는 여러 값 중 쿠키 이름이 accessTokenName 쿠키 찾은 뒤, 그 값을 전달
        Cookie cookie = Arrays.stream(request.getCookies()).filter(c -> c.getName().equals(tokenName)).findAny()
                .orElseGet(() -> new Cookie(tokenName, ""));

        token.set(CmmUtil.nvl(cookie.getValue()));

        log.info(this.getClass().getName() + ".resolveToken End!");

        return token.get();
    }

    /**
     * JWT 토큰(Access Token, Refresh Token) 상태 확인
     *
     * @param token 토큰
     * @return 상태정보(EXPIRED, ACCESS, DENIED)
     */
    public JwtStatus validateToken(String token) {

        if (!token.isEmpty()) {
            try {
                // 보안키 문자들을 JWT Key 형태로 변경하기
                SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

                // JWT 토큰 정보
                Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();

                // 토큰 만료여부 체크
                if (claims.getExpiration().before(new Date())) {
                    return JwtStatus.EXPIRED; // 기간 만료

                } else {
                    return JwtStatus.ACCESS; // 유효한 토큰
                }

            } catch (ExpiredJwtException e) {
                // 만료된 경우에는 refresh token을 확인하기 위해
                return JwtStatus.EXPIRED; // 혹시 몰라서 Exception으로 한번 더 체크 기간 만료

            } catch (JwtException | IllegalArgumentException e) {

                return JwtStatus.DENIED;
            }

        } else {
            return JwtStatus.DENIED;
        }

    }
}