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
@Table(name = "car")
public class Car {
    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    FK (User)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

//    FK (Car_info)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_info_id", nullable = false)
    private CarInfo carInfo;


    //    배터리팩 일련번호
    @Column(name = "pack_code", length = 20, unique = true, nullable = false)
    private String packCode;

    //  차 번호
    @Column(name = "car_number", length = 20, unique = true, nullable = false)
    private String carNumber;

//    생성일시
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    //    활성여부
    @Column(name = "is_activate")
    private Boolean isActivate;


    //    기본값 설정
    @PrePersist
    public void prePersist() {
        this.isActivate = true;
        this.createdAt = LocalDateTime.now();
    }


//    Setter
    public void setActivate(Boolean activate) {
        isActivate = activate;
    }



}
