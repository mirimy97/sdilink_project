package com.sdilink.battery.domain;


import lombok.*;

import javax.persistence.*;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
@Getter
@Table(name = "user_bms")
public class UserBms {

//    user_bms Id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    이름 (본인 확인용)
    @Column(length = 20)
    private String name;

//    생년월일 (본인 확인용)
    @Column(nullable = false, length = 6)
    private String birth;

//    배터리팩 일련번호
    @Column(name = "pack_code", length = 20)
    private String packCode;

    //  차 번호
    @Column(name = "car_number", length = 20, unique = true, nullable = false)
    private String carNumber;

}
