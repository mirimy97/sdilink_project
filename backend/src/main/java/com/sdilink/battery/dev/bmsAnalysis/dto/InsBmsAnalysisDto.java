package com.sdilink.battery.dev.bmsAnalysis.dto;


import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class InsBmsAnalysisDto {

//    급속충전횟수
    private Integer fastCharge;
//    완속충전횟수
    private Integer slowCharge;
//    배터리 동작시간(초)
    private Long totalRuntime;
//    누적 싸이클
    private Integer totalCycle;
//    누적 충전량
    private Float totalCharge;
//    누적 방전량
    private Float totalDischarge;
//    배터리교체예상시기 (남은 사이클)
    private Integer bLeftCycle;
//    누적 주행거리
    private Integer totalDrive;
//    배터리성능상태
    private Float bTotalScore;
}
