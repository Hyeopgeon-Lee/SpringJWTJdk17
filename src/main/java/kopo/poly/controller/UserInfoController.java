package kopo.poly.controller;

import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IUserInfoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * 사용자 정보 조회 컨트롤러.
 * <p>
 * 목적
 * - 요청에 포함된 JWT(쿠키 또는 Authorization 헤더)에서 사용자 식별자(subject)를 읽고,
 * DB에서 해당 사용자의 상세 정보를 조회하여 반환한다.
 * <p>
 * 전제
 * - SecurityConfig에서 /user/** 경로는 인증을 요구하므로, 정상 요청에서는 리소스 서버가
 * 이미 인증을 완료한 상태로 본 메서드에 진입한다. 따라서 일반적으로 jwt는 null이 아니다.
 * - 그래도 방어적으로 jwt == null인 경우에 대한 처리(401)를 넣어 두었다.
 * <p>
 * 참고
 * - @AuthenticationPrincipal Jwt jwt 로 JWT를 직접 주입받는다.
 * 대안으로는 @AuthenticationPrincipal(expression = "subject") String userId 사용도 가능하다.
 */
@Slf4j
@RequestMapping(value = "/user/v1")
@RequiredArgsConstructor
@RestController
public class UserInfoController {

    /**
     * 사용자 조회용 서비스
     */
    private final IUserInfoService userInfoService;

    /**
     * 현재 로그인 사용자의 상세 정보를 반환한다.
     * <p>
     * 반환 정책
     * - 성공(인증됨): 200 OK + CommonResponse<UserInfoDTO>
     * - 인증되지 않음(jwt == null): 401 Unauthorized
     * <p>
     * 주의
     * - 본 엔드포인트는 조회 성격이므로 GET이 더 REST스럽지만,
     * 쿠키 기반 인증/캐시 회피 등의 이유로 POST를 사용할 수도 있다.
     */
    @PostMapping("userInfo")
    public ResponseEntity<CommonResponse<UserInfoDTO>> userInfo(@AuthenticationPrincipal Jwt jwt) throws Exception {
        log.info("{}.userInfo Start!", getClass().getName());

        // 방어적 처리: 보안 설정상 도달하지 않아야 하지만, 혹시 모를 잘못된 호출 대비
        if (jwt == null) {
            log.warn("JWT principal is null - unauthorized access to /user/v1/userInfo");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(CommonResponse.of(
                            HttpStatus.UNAUTHORIZED,
                            HttpStatus.UNAUTHORIZED.series().name(), // "CLIENT_ERROR"
                            UserInfoDTO.builder().build()));
        }

        // JWT의 subject는 발급 시 userId로 설정되어 있음 (JwtTokenService 참조)
        final String userId = jwt.getSubject();

        // 서비스 계층으로 조회 위임
        UserInfoDTO pDTO = UserInfoDTO.builder().userId(userId).build();

        // 존재하지 않는 경우 빈 DTO로 대체 (프런트 단에서 null 체크 대신 빈 객체 처리 가능)
        UserInfoDTO rDTO = Optional.ofNullable(userInfoService.getUserInfo(pDTO))
                .orElseGet(() -> UserInfoDTO.builder().build());

        log.info("{}.userInfo End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), rDTO)
        );
    }
}
