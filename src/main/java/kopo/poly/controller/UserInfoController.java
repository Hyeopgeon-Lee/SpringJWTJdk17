package kopo.poly.controller;

import jakarta.servlet.http.HttpServletRequest;
import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.jwt.JwtTokenProvider;
import kopo.poly.jwt.JwtTokenType;
import kopo.poly.service.IUserInfoService;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;


@Slf4j
@RequestMapping(value = "/user/v1")
@RequiredArgsConstructor
@RestController
public class UserInfoController {

    // 회원 서비스
    private final IUserInfoService userInfoService;

    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping(value = "userInfo")
    public ResponseEntity<CommonResponse> userInfo(HttpServletRequest request) throws Exception {

        log.info(this.getClass().getName() + ".userInfo Start!");

        // 토큰 가져오기
        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request, JwtTokenType.ACCESS_TOKEN));


        // Session 저장된 로그인한 회원아이디 가져오기
        String userId = jwtTokenProvider.getTokenInfo(accessToken).userId();

        UserInfoDTO pDTO = UserInfoDTO.builder().userId(userId).build();

        // 회원정보 조회하기
        UserInfoDTO rDTO = Optional.ofNullable(userInfoService.getUserInfo(pDTO))
                .orElseGet(() -> UserInfoDTO.builder().build());

        log.info(this.getClass().getName() + ".userInfo End!");

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), rDTO));

    }
}

