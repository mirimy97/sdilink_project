package com.sdilink.battery.dev.viewHistory.dto;


import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ViewHistoryRecentDto {

//    ViewHistory Id (View History pk)
    private Long viewHistoryId;
//    Approval Id (해당 조회의 보험사, 차량에 해당하는 승인건 중 가장 최근 객체)
    private Long approvalId;
//    Approval auth time (승인 시간) 만료 여부
    private Boolean isExpired;
//    Car Id - (Car)
    private Long carId;
//    차량 소유주 - (User)
    private String name;
//    차종 id
    private Long carInfoId;
//    차종(모델명) - (CarInfo)
    private String modelName;
//    배터리팩 일련번호 - (Car)
    private String packCode;
//    정보 조회 일시 - (View History)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
    private LocalDateTime createdAt;

}
