package kopo.poly.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import kopo.poly.repository.entity.UserInfoEntity;
import kopo.poly.util.CmmUtil;
import kopo.poly.util.DateUtil;
import kopo.poly.util.EncryptUtil;
import lombok.Builder;

import java.io.Serializable;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserInfoDTO(

        @NotBlank(message = "아이디는 필수 입력 사항입니다.")
        @Size(min = 4, max = 16, message = "아이디는 최소 4글자에서 16글자까지 입력가능합니다.")
        String userId,

        @NotBlank(message = "이름은 필수 입력 사항입니다.")
        @Size(max = 10, message = "이름은 10글자까지 입력가능합니다.")
        String userName,

        @NotBlank(message = "비밀번호는 필수 입력 사항입니다.")
        @Size(max = 16, message = "비밀번호는 16글자까지 입력가능합니다.")
        String password,

        @NotBlank(message = "이메일은 필수 입력 사항입니다.")
        @Size(max = 30, message = "이메일은 30글자까지 입력가능합니다.")
        @Email String email,

        @NotBlank(message = "주소는 필수 입력 사항입니다.")
        @Size(max = 30, message = "주소는 30글자까지 입력가능합니다.")
        String addr1,

        @NotBlank(message = "상세 주소는 필수 입력 사항입니다.")
        @Size(max = 100, message = "상세 주소는 100글자까지 입력가능합니다.")
        String addr2,
        String regId,
        String regDt,
        String chgId,
        String chgDt,
        String roles,

        // 회원가입시, 중복가입을 방지 위해 사용할 변수
        // DB를 조회해서 회원이 존재하면 Y값을 반환함
        // DB테이블에 존재하지 않는 가상의 컬럼(ALIAS)
        String existsYn) implements Serializable {

    /**
     * 패스워드, 권한 등 회원 가입을 위한 정보 만들기
     */
    public static UserInfoDTO createUser(UserInfoDTO pDTO, String password, String roles) throws Exception {

        return UserInfoDTO.builder()
                .userId(pDTO.userId())
                .userName(pDTO.userName())
                .password(password) // Spring Security 생성해준 암호화된 비밀번호
                .email(EncryptUtil.encAES128CBC(pDTO.email()))
                .addr1(pDTO.addr1())
                .addr2(pDTO.addr2())
                .roles(roles) // 권한
                .regId(pDTO.userId())
                .regDt(DateUtil.getDateTime("yyyy-MM-dd hh:mm:ss"))
                .chgId(pDTO.userId())
                .chgDt(DateUtil.getDateTime("yyyy-MM-dd hh:mm:ss")).build();
    }

    /**
     * DTO 결과를 entity 변환하기
     * 이전 실습에서 진행한 Jackson 객체를 통해 처리도 가능함
     */
    public static UserInfoEntity of(UserInfoDTO dto) {

        return UserInfoEntity.builder()
                .userId(dto.userId())
                .userName(dto.userName())
                .password(dto.password())
                .email(dto.email())
                .addr1(dto.addr1())
                .addr2(dto.addr2())
                .roles(dto.roles())
                .regId(dto.regId())
                .regDt(dto.regDt())
                .chgId(dto.chgId())
                .chgDt(dto.chgDt()).build();
    }

    /**
     * JPA로 전달받은 entity 결과를 DTO로 변환하기
     * 이전 실습에서 진행한 Jackson 객체를 통해 처리도 가능함
     */
    public static UserInfoDTO from(UserInfoEntity entity) throws Exception {

        return UserInfoDTO.builder()
                .userId(entity.getUserId())
                .userName(entity.getUserName())
                .password(entity.getPassword())
                .email(EncryptUtil.decAES128CBC(CmmUtil.nvl(entity.getEmail())))
                .addr1(entity.getAddr1())
                .addr2(entity.getAddr2())
                .roles(entity.getRoles())
                .regId(entity.getRegId())
                .regDt(entity.getRegDt())
                .chgId(entity.getChgId())
                .chgDt(entity.getChgDt()).build();
    }
}

