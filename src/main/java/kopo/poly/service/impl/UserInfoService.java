package kopo.poly.service.impl;

import kopo.poly.auth.AuthInfo;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.repository.UserInfoRepository;
import kopo.poly.repository.entity.UserInfoEntity;
import kopo.poly.service.IUserInfoService;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserInfoService implements IUserInfoService {

    private final UserInfoRepository userInfoRepository;

    @Override
    public UserInfoDTO getUserIdExists(UserInfoDTO pDTO) throws Exception {

        log.info(this.getClass().getName() + ".getUserIdExists Start!");

        AtomicReference<UserInfoDTO> atomicReference = new AtomicReference<>(); // 람다로 인해 값을 공유하지 못하여 AtomicReference 사용함

        // ifPresentOrElse 값이 존재할 떄와 값이 존재 안할 때, 수행할 내용을 정의(람다 표현식 사용)
        userInfoRepository.findByUserId(pDTO.userId()).ifPresentOrElse(entity -> {
            atomicReference.set(UserInfoDTO.builder().existsYn("Y").build()); // 객체에 값이 존재한다면...

        }, () -> {
            atomicReference.set(UserInfoDTO.builder().existsYn("N").build()); // 값이 존재하지 않는다면...

        });

        log.info(this.getClass().getName() + ".getUserIdExists End!");

        return atomicReference.get();
    }

    /**
     * Spring Security에서 로그인 처리를 하기 위해 실행하는 함수
     * Spring Security의 인증 기능을 사용하기 위해선 반드시 만들어야 하는 함수
     * <p>
     * Controller로부터 호출되지않고, Spring Security가 바로 호출함
     * <p>
     * 아이디로 검색하고, 검색한 결과를 기반으로 Spring Security가 비밀번호가 같은지 판단함
     * <p>
     * 아이디와 패스워드가 일치하지 않으면 자동으로 UsernameNotFoundException 발생시킴
     *
     * @param userId 사용자 아이디
     */
    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        log.info(this.getClass().getName() + ".loadUserByUsername Start!");

        log.info("userId : " + userId);

        // 로그인 요청한 사용자 아이디를 검색함
        // SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67'
        UserInfoEntity rEntity = userInfoRepository.findByUserId(userId)
                .orElseThrow(() -> new UsernameNotFoundException(userId + " Not Found User"));

        // rEntity 데이터를 DTO로 변환하기
        UserInfoDTO rDTO = UserInfoDTO.from(rEntity);

        // 비밀번호가 맞는지 체크 및 권한 부여를 위해 rDTO를 UserDetails를 구현한 AuthInfo에 넣어주기
        return new AuthInfo(rDTO);
    }

    @Override
    public int insertUserInfo(UserInfoDTO pDTO) {

        log.info(this.getClass().getName() + ".insertUserInfo Start!");

        int res = 0; // 회원가입 성공 : 1, 아이디 중복으로인한 가입 취소 : 2, 기타 에러 발생 : 0

        log.info("pDTO : " + pDTO);

        // 회원 가입 중복 방지를 위해 DB에서 데이터 조회
        Optional<UserInfoEntity> rEntity = userInfoRepository.findByUserId(pDTO.userId());

        // 값이 존재한다면... (이미 회원가입된 아이디)
        if (rEntity.isPresent()) {
            res = 2;

        } else {
            // 회원가입을 위한 Entity 생성
            UserInfoEntity pEntity = UserInfoDTO.of(pDTO);

            // 회원정보 DB에 저장
            userInfoRepository.save(pEntity);

            res = 1;

        }

        log.info(this.getClass().getName() + ".insertUserInfo End!");

        return res;
    }

    @Override
    public UserInfoDTO getUserInfo(UserInfoDTO pDTO) throws Exception {

        log.info(this.getClass().getName() + ".getUserInfo Start!");

        // 회원아이디
        String user_id = CmmUtil.nvl(pDTO.userId());

        log.info("user_id : " + user_id);

        // SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67' 쿼리 실행과 동일
        UserInfoDTO rDTO = UserInfoDTO.from(userInfoRepository.findByUserId(user_id).orElseThrow());

        log.info(this.getClass().getName() + ".getUserInfo End!");

        return rDTO;
    }
}
