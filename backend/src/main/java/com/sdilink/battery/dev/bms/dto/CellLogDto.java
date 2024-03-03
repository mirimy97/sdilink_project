package com.sdilink.battery.dev.bms.dto;


import java.time.LocalDateTime;

import lombok.*;

import javax.persistence.Column;

import com.fasterxml.jackson.annotation.JsonFormat;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class CellLogDto {

    private Long id;

    private String cellCode;

    private Float voltageC;

    private Float outlier;

    private Integer isNormal;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdAt;
}
