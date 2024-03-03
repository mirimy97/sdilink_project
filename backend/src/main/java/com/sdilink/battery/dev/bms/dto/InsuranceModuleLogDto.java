package com.sdilink.battery.dev.bms.dto;

import java.util.List;

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
public class InsuranceModuleLogDto {

	private Long id;

	private String moduleCode;

	private Float temp;

	private Float voltage;

	private List<CellLogDto> cellLogList;
}
