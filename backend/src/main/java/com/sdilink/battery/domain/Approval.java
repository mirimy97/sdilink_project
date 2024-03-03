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
@Table(name = "approval")
public class Approval {

    //    승인id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    FK (Car)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_id", nullable = false)
    private Car car;

//    FK (Insurance)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "insurance_id", nullable = false)
    private Insurance insurance;

//    승인시간 (최초 null, 승인 시 할당)
    @Column(name = "auth_time")
    private LocalDateTime authTime;

    //    생성일시
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    //    승인여부
    @Column(name = "is_approve", columnDefinition = "TINYINT(2)")
    private Integer isApprove;


    //    기본값 설정
    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
        this.isApprove = 0;
    }


//      Setter
    public void setIsApprove(int isApprove) {
        this.isApprove = isApprove;
    }

//    승인시간 현재로 set
    public void setAuthTime() {
        this.authTime = LocalDateTime.now();
    }


}
