package kopo.poly.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.auth.AuthInfo;
import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.MsgDTO;
import kopo.poly.dto.TokenDTO;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.jwt.JwtTokenProvider;
import kopo.poly.jwt.JwtTokenType;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@Slf4j
@RequestMapping(value = "/login/v1")
@RequiredArgsConstructor
@RestController
public class LoginController {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 로그인 성공 시 호출되는 메서드
     * 사용자 정보를 기반으로 Access Token과 Refresh Token을 생성하여 쿠키에 저장
     */
    @PostMapping(value = "loginSuccess")
    public ResponseEntity<CommonResponse<MsgDTO>> loginSuccess(@AuthenticationPrincipal AuthInfo authInfo,
                                                               HttpServletResponse response) {

        log.info("{}.loginSuccess Start!", getClass().getName());

        // Spring Security에서 인증된 사용자 정보 가져오기
        UserInfoDTO rDTO = Optional.ofNullable(authInfo.userInfoDTO()).orElseGet(() -> UserInfoDTO.builder().build());

        String userId = CmmUtil.nvl(rDTO.userId());
        String userName = CmmUtil.nvl(rDTO.userName());
        String userRoles = CmmUtil.nvl(rDTO.roles());

        log.info("rDTO : {}", rDTO);

        // JWT 생성에 필요한 사용자 정보 객체 생성
        TokenDTO tDTO = TokenDTO.builder().userId(userId).userName(userName).role(userRoles).build();

        // Access Token 생성 및 쿠키 설정
        String accessToken = jwtTokenProvider.createToken(tDTO, JwtTokenType.ACCESS_TOKEN);

        ResponseCookie accessCookie = ResponseCookie.from(accessTokenName, accessToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(accessTokenValidTime)
                .httpOnly(true)
                .build();

        response.setHeader("Set-Cookie", accessCookie.toString());

        // Refresh Token 생성 및 쿠키 설정
        String refreshToken = jwtTokenProvider.createToken(tDTO, JwtTokenType.REFRESH_TOKEN);

        ResponseCookie refreshCookie = ResponseCookie.from(refreshTokenName, refreshToken)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(refreshTokenValidTime)
                .httpOnly(true)
                .build();

        response.addHeader("Set-Cookie", refreshCookie.toString());

        // 사용자에게 반환할 메시지 구성
        MsgDTO dto = MsgDTO.builder().result(1).msg(userName + "님 로그인이 성공하였습니다.").build();

        log.info("{}.loginSuccess End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto));
    }

    /**
     * 로그인 실패 시 호출되는 메서드
     * 단순 실패 메시지를 반환함
     */
    @PostMapping(value = "loginFail")
    public ResponseEntity<CommonResponse<MsgDTO>> loginFail() {

        log.info("{}.loginFail Start!", getClass().getName());

        MsgDTO dto = MsgDTO.builder().result(0).msg("아이디, 패스워드가 일치하지 않습니다.").build();

        log.info("{}.loginFail End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto));
    }

    /**
     * 현재 로그인된 사용자 정보를 반환하는 메서드
     * Access Token이 없으면 비로그인 상태로 간주
     */
    @PostMapping(value = "loginInfo")
    public ResponseEntity<CommonResponse<UserInfoDTO>> loginInfo(HttpServletRequest request) {

        log.info("{}.loginInfo Start!", getClass().getName());

        // 쿠키에서 Access Token 추출
        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.ACCESS_TOKEN));

        UserInfoDTO dto;

        if (accessToken.isEmpty()) {
            // Access Token 없으면 비로그인 처리
            dto = UserInfoDTO.builder().userId("").userName("").roles("").build();

        } else {
            // Access Token 유효하면 사용자 정보 추출
            TokenDTO tokenDTO = jwtTokenProvider.getTokenInfo(accessToken);

            dto = UserInfoDTO.builder()
                    .userId(tokenDTO.userId())
                    .userName(tokenDTO.userName())
                    .roles(tokenDTO.role())
                    .build();
        }

        log.info("{}.loginInfo End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto));
    }
}
