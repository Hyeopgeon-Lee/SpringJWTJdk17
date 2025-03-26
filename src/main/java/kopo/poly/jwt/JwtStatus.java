package kopo.poly.jwt;

public enum JwtStatus {
    ACCESS,  // 유효한 토큰
    DENIED,  // 유효하지 않은 토큰
    EXPIRED; // 만료된 토큰

    /**
     * 만료되었거나 거부된 상태인지 확인
     */
    public boolean isInvalid() {
        return this == DENIED || this == EXPIRED;
    }

    /**
     * 토큰이 정상 상태인지 확인
     */
    public boolean isValid() {
        return this == ACCESS;
    }

    /**
     * 만료 여부만 확인
     */
    public boolean isExpired() {
        return this == EXPIRED;
    }
}
