package com.sdilink.battery.domain;


import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@ToString
@Getter
@Table(name = "pack_log")
public class PackLog {

    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // FK (Car)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_id", nullable = false)
    private Car car;

    // 배터리팩 일련번호
    @Column(name = "pack_code", length = 20, nullable = false)
    private String packCode;

    // 전압
    @Column(name = "voltage_p")
    private Float voltageP;

    // 전류
    @Column
    private Float current;

    // 온도
    @Column(name = "temp_p")
    private Float tempP;

    // 상태
    @Column(columnDefinition = "TINYINT(2)")
    private Integer status;

    // 용량
    @Column
    private Float capacity;

    // SOC
    @Column
    private Float soc;

    // SOH
    @Column
    private Float soh;

    // 충전사이클
    @Column
    private Integer cycle;

    // 생성시간 (자동생성X , iot 데이터로 저장함)
    @Column(name = "created_at")
    private LocalDateTime createdAt;




}
