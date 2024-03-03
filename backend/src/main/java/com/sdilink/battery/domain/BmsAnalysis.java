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
@Table(name = "bms_analysis")
public class BmsAnalysis {

    //    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //    FK (User)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_id", nullable = false)
    private Car car;

    //    생성일시
    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

//    급속 충전 횟수
    @Column(name = "fast_charge")
    private Integer fastCharge;

//    완속 충전 횟수
    @Column(name = "slow_charge")
    private Integer slowCharge;

//    누적 충전량
    @Column(name = "total_charge")
    private Float totalCharge;

//    누적 방전량
    @Column(name = "total_discharge")
    private Float totalDischarge;

//    누적 동작시간
    @Column(name = "total_runtime")
    private Long totalRuntime;

//   누적 싸이클
    @Column(name = "total_cycle")
    private Integer totalCycle;
    
//    누적 주행거리
    @Column(name = "total_drive")
    private Integer totalDrive;

//    운전 습관 점수
    @Column(name = "drive_score")
    private Float driveScore;

//    배터리 수명 점수
    @Column(name = "b_life_score")
    private Float bLifeScore;

//    배터리 종합 점수
    @Column(name = "b_total_score")
    private Float bTotalScore;

//    배터리 남은 충전 사이클(회) (교체예상시기)
    @Column(name = "b_left_cycle")
    private Integer bLeftCycle;

//    연료 비용 절감 효과 (원)
    @Column(name = "fuel_save")
    private Float fuelSave;

//    탄소 절감 효과 (kg)
    @Column(name = "carbon_save")
    private Float carbonSave;

//    나무 심은 효과 (그루)
    @Column(name = "tree_save")
    private Integer treeSave;

    //    기본값 설정
    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

}
