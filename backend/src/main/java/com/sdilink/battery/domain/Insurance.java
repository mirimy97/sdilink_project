package com.sdilink.battery.domain;

import lombok.*;
import net.bytebuddy.asm.Advice;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
@Getter
@Table(name = "insurance")
public class Insurance {
    //    seq
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

	@Column(name = "account_id", length=50, nullable = false, unique = true)
	private String accountId;


    //    로그인 비밀번호
    @Column(name = "account_pwd", nullable = false, length = 100)
    private String accountPwd;

//    보험사명
    @Column(nullable = false, length = 20)
    private String name;

    //    활성여부
    @Column(name = "is_activate")
    private Boolean isActivate;

    //    삭제여부
    @Column(name = "is_withdraw")
    private Boolean isWithdraw;

    //  프로필 이미지 경로
    @Column(name = "image_src", length = 100)
    private String imageSrc;

    //    생성일시
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    //  최근 접속 날짜
    private LocalDateTime loginDate;

    //api token
    private String apiToken;

    private LocalDateTime tokenDate;


    //    기본값 설정
    @PrePersist
    public void prePersist() {
        this.isActivate = true;
        this.isWithdraw = false;
    }

    // api 토큰 설정
    public void setApiToken(String apiToken) {
        this.apiToken = apiToken;
        this.tokenDate = LocalDateTime.now();
    }

    //토큰 삭제
    public boolean deleteApiToken() {
        if(apiToken == null) return false;
        this.apiToken = null;
        this.tokenDate = null;
        return true;
    }

    public void setLoginDate() {
        loginDate = LocalDateTime.now();
    }

}
