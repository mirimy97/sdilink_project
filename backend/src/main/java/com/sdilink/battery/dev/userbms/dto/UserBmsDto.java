package com.sdilink.battery.dev.userbms.dto;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

import com.sdilink.battery.dev.bms.dto.ModuleLogDto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class UserBmsDto {

	private Long bmsId;

	private Float soc;

	private Float voltage;

	private Float current;

	private Float temp;

	private Float bTotalScore;

	private Float totalCharge;

	private Float totalDischarge;

	private Integer fastCharge;

	private Long totalRuntime;


	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
	private LocalDateTime createdAt;


	private List<ModuleLogDto> modules;
}
