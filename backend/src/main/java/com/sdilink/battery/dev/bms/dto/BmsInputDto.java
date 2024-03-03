package com.sdilink.battery.dev.bms.dto;


import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class BmsInputDto {

//    private Long id;
    /* 팩 정보 */
    private String packCode;
    private Float voltageP;
    private Float current;
    private Float tempP;
    private Integer status;
    private Float capacity;
    private Float soc;
    private Float soh;
    private Integer cycle;

    /* 모듈 정보 */
    private String moduleCode;
    private Float voltageM;
    private Float tempM;

    /* 셀 정보 */
    private String cellCode;
    private Float voltageC;

    /* 공통 */
    private LocalDateTime createdAt;






}
