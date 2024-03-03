package com.sdilink.battery.dev.userbms.dto;

import lombok.*;

import java.util.List;
import java.util.Map;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class UserBmsPredictDto {

//    예상 주행 가능 거리 (km)
    private Float driveDistance;

//    배터리 성능 상태 (현재 SoH)
    private Float soh;

//    남은 cycle
    private Integer leftCycle;

////    이상치 가장 많이 나온 모듈 - 건수
//    private Integer topOutlierCnt;
//
////    이상치 가장 많이 나온 모듈 - 코드
//    private String topOutlierCode;

//    이상치 그래프
    private List<Map<String, Object>> outlierGraph;

//    가장 최근 주행 시간 (분)
    private Long driveTime;
}
