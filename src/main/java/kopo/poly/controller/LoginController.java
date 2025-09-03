package kopo.poly.controller;

import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.auth.AuthInfo;
import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.MsgDTO;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IJwtTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 로그인(인증) 및 현재 로그인 사용자 조회를 담당하는 컨트롤러.
 * <p>
 * 구성 요약
 * - /login/v1/loginProc : 사용자 인증을 수행하고 Access/Refresh 토큰을 쿠키로 발급한다.
 * - /login/v1/loginInfo : 요청에 포함된 JWT(쿠키 또는 Authorization 헤더)를 바탕으로
 * 현재 로그인 사용자의 최소 정보를 반환한다.
 * <p>
 * 동작 전제
 * - SecurityConfig에서 oauth2ResourceServer().jwt()가 설정되어 있어야 하며,
 * BearerTokenResolver가 Access Token을 쿠키에서 우선 읽도록 구성되어 있어야 한다.
 * - AuthenticationManager는 UserDetailsService/PasswordEncoder를 통해
 * 사용자 아이디/비밀번호를 검증한다.
 * <p>
 * 예외 처리
 * - 인증 실패 시 발생하는 AuthenticationException은 전역 핸들러(AuthExceptionHandler)가
 * 401 응답과 표준 메시지로 변환한다.
 */
@Slf4j
@RequestMapping(value = "/login/v1")
@RequiredArgsConstructor
@RestController
public class LoginController {

    /**
     * 스프링 시큐리티 인증 진입점. UsernamePasswordAuthenticationToken을 받아 인증을 수행한다.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * JWT 발급 및 쿠키 저장을 담당하는 서비스(인터페이스). 구현체는 JwtTokenService.
     */
    private final IJwtTokenService jwtTokenService;

    /**
     * 로그인 처리 엔드포인트.
     * <p>
     * 입력
     * - 본 예제에서는 UserInfoDTO를 사용하지만, 실제로는 userId/password만 사용한다.
     * (회원가입 DTO와 혼용되는 것을 피하려면 로그인 전용 DTO를 별도로 두는 것을 권장)
     * <p>
     * 처리 절차
     * 1) AuthenticationManager.authenticate(...) 호출로 사용자 인증 수행
     * 2) 인증 성공 시, Principal(AuthInfo)에서 UserInfoDTO 추출
     * 3) JwtTokenService를 통해 Access/Refresh 토큰을 발급하고 HttpOnly 쿠키로 세팅
     * <p>
     * 반환
     * - 성공 시 200 OK + { result:1, msg:"로그인 성공" }
     * - 실패 시 AuthenticationException이 발생하며, 전역 핸들러가 401 응답으로 전환
     */
    @PostMapping("loginProc")
    public ResponseEntity<CommonResponse<MsgDTO>> loginProc(@RequestBody UserInfoDTO pDTO,
                                                            HttpServletResponse response) {
        log.info("{}.loginProc Start!", getClass().getName());

        // 1) 사용자가 보낸 자격 증명으로 인증 시도
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(pDTO.userId(), pDTO.password())
        );

        // 2) 인증 성공 시, 커스텀 Principal(AuthInfo)에서 애플리케이션 도메인 사용자 정보 획득
        AuthInfo principal = (AuthInfo) auth.getPrincipal();
        UserInfoDTO u = principal.userInfoDTO();

        // 3) Access/Refresh 토큰 발급 및 HttpOnly 쿠키로 저장
        jwtTokenService.issueTokens(u, response);

        // 4) 통일된 응답 포맷으로 성공 메시지 반환
        MsgDTO dto = MsgDTO.builder()
                .result(1)
                .msg("로그인 성공")
                .build();

        log.info("{}.loginProc End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto)
        );
    }

    /**
     * 현재 로그인된 사용자 정보를 반환하는 엔드포인트.
     * <p>
     * 동작 방식
     * - SecurityConfig의 리소스 서버가 요청에서 JWT를 읽어 인증을 완료하면,
     * 컨트롤러 파라미터로 Jwt 객체를 주입(@AuthenticationPrincipal)해 준다.
     * - JWT가 없거나 유효하지 않아 인증이 되지 않은 경우 jwt 파라미터는 null이다.
     * <p>
     * 주의
     * - 이 메서드는 간단히 JWT의 클레임(sub, username, roles)만 읽어 반환한다.
     * 상세한 사용자 정보가 필요하면 서비스 계층에서 DB 조회를 수행하도록 확장할 수 있다.
     * <p>
     * 반환
     * - 로그인 상태: JWT의 subject/claims 기반 UserInfoDTO
     * - 비로그인 상태: 빈 값의 UserInfoDTO (userId/userName/roles 빈 문자열)
     */
    @PostMapping("loginInfo")
    public ResponseEntity<CommonResponse<UserInfoDTO>> loginInfo(
            @AuthenticationPrincipal Jwt jwt) {

        log.info("{}.loginInfo Start!", getClass().getName());

        UserInfoDTO dto;

        if (jwt == null) {
            // 비로그인: JWT가 전달되지 않았거나 유효하지 않아 인증이 이루어지지 않은 상태
            dto = UserInfoDTO.builder()
                    .userId("")
                    .userName("")
                    .roles("")
                    .build();

        } else {
            // 로그인됨: JWT의 표준 subject(sub)와 커스텀 클레임(username, roles) 사용
            String userId = jwt.getSubject();                // sub
            String userName = jwt.getClaim("username");      // 발급 시 JwtTokenService에서 넣은 클레임
            List<String> roles = jwt.getClaim("roles"); // List<String> 형태의 권한 목록
            String rolesCsv = (roles == null) ? "" : String.join(",", roles);

            dto = UserInfoDTO.builder()
                    .userId(userId)
                    .userName(userName)
                    .roles(rolesCsv)
                    .build();
        }

        log.info("{}.loginInfo End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto)
        );
    }
}
