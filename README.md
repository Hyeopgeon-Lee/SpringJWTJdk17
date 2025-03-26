# 🌱 스프링 시큐리티와 JWT를 활용한 웹 프로그래밍

> **Java 17 기반 Spring Boot와 JWT를 활용한 웹 프로그래밍 실습**  
> Spring Security와 JWT를 사용하여 인증 및 인가 기능이 구현된 웹 애플리케이션입니다.  
> 데이터베이스는 **MariaDB**를 사용하여 구현되었습니다.  
> 공유되는 프로그래밍 코드는 한국폴리텍대학 서울강서캠퍼스 빅데이터과 수업에서 사용된 코드입니다.

---

### 📚 **작성자**
- **한국폴리텍대학 서울강서캠퍼스 빅데이터과**  
- **이협건 교수**  
- ✉️ [hglee67@kopo.ac.kr](mailto:hglee67@kopo.ac.kr)  
- 🔗 [빅데이터학과 입학 상담 오픈채팅방](https://open.kakao.com/o/gEd0JIad)

---

## 🚀 주요 실습 내용

1. **Spring Security 설정 및 사용자 인증 구현**
2. **JWT 토큰 생성 및 검증**
3. **JWT를 활용한 인증 및 인가 로직 구현**
4. **MariaDB를 활용한 회원가입 및 로그인**

---

## 🚀 주요 적용 프레임워크

1. **Spring Boot Frameworks**
2. **Thymeleaf Frameworks**
3. **Spring Data JPA**
4. **Spring Security**
5. **JWT**
6. **MariaDB**

---

## 📩 문의 및 입학 상담

- 📧 **이메일**: [hglee67@kopo.ac.kr](mailto:hglee67@kopo.ac.kr)  
- 💬 **입학 상담 오픈채팅방**: [바로가기](https://open.kakao.com/o/gEd0JIad)

---

## 💡 **우리 학과 소개**
- 한국폴리텍대학 서울강서캠퍼스 빅데이터과는 **클라우드 컴퓨팅, 인공지능, 빅데이터 기술**을 활용하여 소프트웨어 개발자를 양성하는 학과입니다.  
- 학과에 대한 더 자세한 정보는 [학과 홈페이지](https://www.kopo.ac.kr/kangseo/content.do?menu=1547)를 참고하세요.

---

## 📦 **설치 및 실행 방법**

### 1. 레포지토리 클론
- 아래 명령어를 실행하여 레포지토리를 클론합니다.

```bash
git clone https://github.com/Hyeopgeon-Lee/SpringJWTJdk17.git
cd SpringJWTJdk17
```

### 2. MariaDB 설정
- application.yml 또는 application.properties 파일에서 MariaDB 연결 정보를 설정합니다.

```yaml
spring:
  datasource:
    url: jdbc:mariadb://localhost:3306/your_database
    username: your_username
    password: your_password
```

### 3. 의존성 설치 및 빌드
- Gradle을 사용하여 의존성을 설치하고 애플리케이션을 빌드합니다.

```bash
./gradlew build
```

### 4. 애플리케이션 실행
- 아래 명령어를 실행하여 애플리케이션을 시작합니다.

```bash
./gradlew bootRun
```

