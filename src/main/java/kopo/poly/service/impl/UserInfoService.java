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
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserInfoService implements IUserInfoService {

    private final UserInfoRepository userInfoRepository;

    @Transactional(readOnly = true) // 조회 전용 트랜잭션:
    // - 영속성 컨텍스트의 Dirty Checking/Flush 생략 → 불필요한 쓰기 방지
    // - 일부 DB/드라이버에 read-only 힌트 전달(최적화 가능)
    @Override
    public UserInfoDTO getUserIdExists(UserInfoDTO pDTO) {

        // Repository에서 userId로 조회
        // - 반환 타입이 Optional<UserInfoEntity>라서 null 대신 "값이 있음/없음"을 표현
        return userInfoRepository.findByUserId(pDTO.userId())

                // [값이 있는 경우] ⇒ 해당 아이디가 존재하므로 existsYn = "Y" 인 DTO를 만들어 반환
                // - 엔티티의 상세 필드는 이 시나리오에 필요 없어서 만들지 않음(불필요한 매핑 비용 절감)
                .map(e -> UserInfoDTO.builder()
                        .existsYn("Y")
                        .build())

                // [값이 없는 경우] ⇒ 해당 아이디가 존재하지 않음 → existsYn = "N" 인 DTO 생성
                // - orElseGet(Supplier)은 "없을 때만" 람다를 실행함
                //   (orElse(...)는 항상 인자를 먼저 만들어 성능상 손해가 될 수 있음)
                .orElseGet(() -> UserInfoDTO.builder()
                        .existsYn("N")
                        .build());
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
        log.info("{}.loadUserByUsername Start!", this.getClass().getName());

        log.info("userId : {}", userId);

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
    @Transactional // 트랜잭션 보장 (쓰기 작업 포함이므로 readOnly=false가 기본)
    public int insertUserInfo(UserInfoDTO pDTO) {

        log.info("{}.insertUserInfo Start!", this.getClass().getName());

        // 반환 코드: 1 = 가입 성공, 2 = 아이디 중복, 0 = 기타 예외
        int res;

        log.info("pDTO : {}", pDTO);

        try {
            // 1. 회원 아이디 중복 여부 확인
            boolean exists = userInfoRepository.existsById(pDTO.userId());

            if (exists) {
                // 이미 같은 아이디가 존재 → 중복 가입 방지
                res = 2;

            } else {
                // 2. DTO → Entity 변환
                UserInfoEntity pEntity = UserInfoDTO.of(pDTO);

                // 3. DB 저장
                userInfoRepository.save(pEntity);

                res = 1;
            }

        } catch (Exception e) {
            log.error("insertUserInfo error", e);
            res = 0; // 예외 발생 시 0 반환
        }

        log.info("{}.insertUserInfo End! res={}", this.getClass().getName(), res);

        return res;
    }


    @Override
    public UserInfoDTO getUserInfo(UserInfoDTO pDTO) throws Exception {

        log.info("{}.getUserInfo Start!", this.getClass().getName());

        // 회원아이디
        String user_id = CmmUtil.nvl(pDTO.userId());

        log.info("user_id : {}", user_id);

        // SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67' 쿼리 실행과 동일
        UserInfoDTO rDTO = UserInfoDTO.from(userInfoRepository.findByUserId(user_id).orElseThrow());

        log.info("{}.getUserInfo End!", this.getClass().getName());

        return rDTO;
    }
}
