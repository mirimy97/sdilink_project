package com.sdilink.battery.dev.carinfo.dto;


import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class CarInfoSimpleDto {

    //    id
    private Long id;

    //    모델명
    private String modelName;

    //    제조사
    private String maker;

}
