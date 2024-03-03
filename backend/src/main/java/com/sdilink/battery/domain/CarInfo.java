package com.sdilink.battery.domain;


import lombok.*;

import javax.persistence.*;

@Entity
@NoArgsConstructor
@Builder
@AllArgsConstructor
@ToString
@Getter
@Table(name = "car_info")
public class CarInfo {

//    id
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    모델명
    @Column(name = "model_name")
    private String modelName;

//    제조사
    @Column
    private String maker;

//    연비(전비)
    @Column
    private Float efficiency;

//    정원
    @Column(name = "people_capacity")
    private Integer peopleCapacity;

//    구동방식
    @Column(name = "driving_method")
    private String drivingMethod;

//    배터리 종류
    @Column(name = "battery_kind")
    private String batteryKind;

//    배터리 용량
    @Column(name = "battery_capacity")
    private Float batteryCapacity;

//    주행거리
    @Column
    private Integer distance;

}
