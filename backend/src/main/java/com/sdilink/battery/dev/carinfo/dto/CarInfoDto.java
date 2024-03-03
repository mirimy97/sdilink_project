package com.sdilink.battery.dev.carinfo.dto;


import lombok.*;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class CarInfoDto {
    //    id
    private Long id;

    //    모델명
    private String modelName;

    //    제조사
    private String maker;

    //    연비(전비)
    private Float efficiency;

    //    정원
    private Integer peopleCapacity;

    //    구동방식
    private String drivingMethod;

    //    배터리 종류
    private String batteryKind;

    //    배터리 용량
    private Float batteryCapacity;

    //    주행거리
    private Integer distance;

}
