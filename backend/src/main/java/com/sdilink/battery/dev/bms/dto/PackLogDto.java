package com.sdilink.battery.dev.bms.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

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
public class PackLogDto {

	private Long id;
	private String packCode;

	//전압
	private Float voltageP;

	//전류
	private Float current;

	//온도
	private Float tempP;

	//상태
	private String status;


	private Float capacity;

	private Float soc;

	private Float soh;

	private Integer cycle;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
	private LocalDateTime createdAt;


}
