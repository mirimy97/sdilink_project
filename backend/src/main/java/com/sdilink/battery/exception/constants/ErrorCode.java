package com.sdilink.battery.exception.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ErrorCode {

    // 204 : No Content
    NO_MATCH_CAR(404, "일치하는 차 정보가 없습니다."),

    NO_MATCH_USER(204, "일치하는 유저 정보가 없습니다."),

    // 400 : 잘못된 요청
    REQUEST_PARAMETER(400, "요청 파라미터 값이 올바르지 않습니다."),

    // 401 : 접근 권한이 없음
    NO_AUTHORITY(401, "접근 권한이 없습니다." ),

    TOKEN_EXPIRED(401, "토큰이 만료되었습니다. 다시 로그인해주세요."),

    // 403: Forbidden
    PASSWORD_ERROR(403, "비밀번호가 일치하지 않습니다."),

    APPROVAL_DENIED(403, "최근 3일 이내 보낸 대기 중인 승인 요청이 있습니다."),

    // 404: 잘못된 리소스 접근
    NOT_FOUND_ENTITY(404, "해당 객체를 찾지 못했습니다."),
    NOT_FOUND_USER(404, "존재하지 않는 이메일입니다."),

    NOT_FOUND_API_TOKEN(404, "API token 이 존재하지 않습니다."),

    //409 : 중복된 리소스
    ALREADY_EXIST_USER(409, "이미 존재하는 이메일입니다."),


    //500 : INTERNAL SERVER ERROR
    INTERNAL_SERVER_ERROR(500, "서버 내부 에러입니다.");



    private final int status;
    private final String message;
}
