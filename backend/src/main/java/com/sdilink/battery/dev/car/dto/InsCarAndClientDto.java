package com.sdilink.battery.dev.car.dto;


import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class InsCarAndClientDto {

//    고객 신상정보
    private String name;
    private String birth;

//    차종 정보
    private Long carInfoId;
    private String modelName;

//    차량 정보
    private String carNumber;
    private String packCode;


}
