package com.sdilink.battery.dev.bmsAnalysis.dto;

import lombok.*;

import javax.persistence.Column;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class BmsEchoDto {

    //    연료 비용 절감 효과 (원)
    private Float fuelSave;

    //    탄소 절감 효과 (kg)
    private Float carbonSave;

    //    나무 심은 효과 (그루)
    private Integer treeSave;

}
