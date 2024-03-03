package com.sdilink.battery.domain;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@ToString
@Getter
@Table(name = "user")
public class User {

//    seq
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    로그인 아이디
    @Column(name = "user_id",unique = true, nullable = false, length = 20)
    private String userId;


//    로그인 비밀번호
    @Column(name = "user_pwd", nullable = false, length = 100)
    private String userPwd;

//    생년월일 (차량 매핑용 필수)
    @Column(nullable = false, length = 6)
    private String birth;

//    이름 (차량 매핑용 필수)
    @Column(nullable = false, length = 20)
    private String name;

//    가입일(생성일시)
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

//    최근활동일
    @CreatedDate
    @Column(name = "last_act_date")
    private LocalDateTime lastActDate;

//    활성여부
    @Column(name = "is_activate")
    private Boolean isActivate;

//    삭제여부
    @Column(name = "is_withdraw")
    private Boolean isWithdraw;

//    인증여부
    @Column(name = "is_auth")
    private Boolean isAuth;


//    기본값 설정
    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.lastActDate = LocalDateTime.now();
        this.isActivate = true;
        this.isWithdraw = false;
        this.isAuth = false;
    }

}
