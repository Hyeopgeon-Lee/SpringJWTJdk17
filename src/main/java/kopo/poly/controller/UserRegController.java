package kopo.poly.controller;

import jakarta.validation.Valid;
import kopo.poly.auth.UserRole;
import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.MsgDTO;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.service.IUserInfoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping(value = "/reg/v1")
@RequiredArgsConstructor
@RestController
public class UserRegController {

    private final IUserInfoService userInfoSsService;

    // Spring Security에서 제공하는 비밀번호 암호화 객체 (BCrypt 해시 함수)
    private final PasswordEncoder bCryptPasswordEncoder;

    /**
     * 입력된 아이디의 존재 여부를 체크하는 API
     *
     * @param pDTO 사용자로부터 전달받은 ID
     * @return 존재 여부를 담은 UserInfoDTO
     */
    @PostMapping(value = "getUserIdExists")
    public ResponseEntity<CommonResponse<UserInfoDTO>> getUserIdExists(@RequestBody UserInfoDTO pDTO)
            throws Exception {

        log.info("{}.getUserIdExists Start!", getClass().getName());

        UserInfoDTO rDTO = userInfoSsService.getUserIdExists(pDTO);

        log.info("{}.getUserIdExists End!", getClass().getName());

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), rDTO));
    }

    /**
     * 사용자 회원가입 처리 API
     * - 유효성 검증 처리
     * - 패스워드 암호화
     * - 가입 실패/성공 메시지 반환
     *
     * @param pDTO          사용자로부터 입력받은 회원가입 정보
     * @param bindingResult 유효성 검증 결과 객체
     * @return 처리 결과 메시지를 담은 CommonResponse
     */
    @PostMapping(value = "insertUserInfo")
    public ResponseEntity<?> insertUserInfo(@Valid @RequestBody UserInfoDTO pDTO, BindingResult bindingResult) {

        log.info("{}.insertUserInfo Start!", getClass().getName());

        // 1. 유효성 검증 실패 시 에러 메시지 반환
        if (bindingResult.hasErrors()) {
            return CommonResponse.getErrors(bindingResult);
        }

        int res = 0; // 회원가입 처리 결과 코드
        String msg = ""; // 처리 결과 메시지
        MsgDTO dto; // 응답 메시지 객체

        log.info("pDTO : {}", pDTO);

        try {
            // 2. 전달받은 회원 정보에 비밀번호 암호화 및 권한 추가
            UserInfoDTO nDTO = UserInfoDTO.createUser(
                    pDTO,
                    bCryptPasswordEncoder.encode(pDTO.password()),
                    UserRole.USER.getValue()
            );

            // 3. 회원가입 처리
            res = userInfoSsService.insertUserInfo(nDTO);

            log.info("회원가입 결과(res) : {}", res);

            // 4. 처리 결과 메시지 구성
            if (res == 1) {
                msg = "회원가입되었습니다.";
            } else if (res == 2) {
                msg = "이미 가입된 아이디입니다.";
            } else {
                msg = "오류로 인해 회원가입이 실패하였습니다.";
            }

        } catch (Exception e) {
            msg = "실패하였습니다. : " + e;
            res = 2;
            log.error("회원가입 중 예외 발생", e);

        } finally {
            dto = MsgDTO.builder().result(res).msg(msg).build();
            log.info("{}.insertUserInfo End!", getClass().getName());
        }

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto));
    }

}
