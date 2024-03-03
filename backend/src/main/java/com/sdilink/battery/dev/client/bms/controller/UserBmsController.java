package com.sdilink.battery.dev.client.bms.controller;


import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.dev.bms.dto.PackGraphDto;
import com.sdilink.battery.dev.bmsAnalysis.dto.BmsEchoDto;
import com.sdilink.battery.dev.client.bms.service.ModuleLogService;
import com.sdilink.battery.dev.userbms.dto.UserBmsPredictDto;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.security.SecurityService;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sdilink.battery.dev.userbms.dto.UserBmsDto;
import com.sdilink.battery.dev.client.bms.service.UserBmsService;

import io.swagger.annotations.Api;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/client/bms/")
@Api(tags = {"개인사용자 - BMS 데이터"})
public class UserBmsController {

	private final UserBmsService userBmsService;
	private final ModuleLogService moduleLogService;

	private final SecurityService securityService;


	@ApiOperation(value = "1팩 & 8모듈 정보 조회")
	@GetMapping("/cars/{carId}")
	public ResponseEntity<?> getBmsData(@PathVariable(value = "carId", required = true) Long carId) {

		UserBmsDto userBmsDto = userBmsService.getBmsData(carId);
		return ResponseEntity.ok(userBmsDto);
	}

	@ApiOperation(value = "1모듈 & 12셀 정보 조회")
	@GetMapping("/modules/{moduleLogId}")
	public ResponseEntity<Object> getCellDataByModuleId(@PathVariable Long moduleLogId) {

		List<CellLogDto> cellList = moduleLogService.getCellDataByModuleId(moduleLogId);

		return ResponseEntity.ok(cellList);
	}

	@ApiOperation(value = "전압, 전류, 온도 그래프 데이터 조회")
	@GetMapping("/cars/graph/{carId}")
	public ResponseEntity<?> getBmsGraphData(@PathVariable(value = "carId", required = true) Long carId) {

		List<PackGraphDto> packGraphDtoList = userBmsService.getBmsGraphData(carId);
		return ResponseEntity.ok(packGraphDtoList);
	}

	@ApiOperation(value = "SoH 그래프 데이터 조회")
	@GetMapping("/cars/{carId}/graph/soh")
	public ResponseEntity<Object> getSoHGraphData(@PathVariable Long carId) {

		List<Map<String, Object>> sohGraphDatas = userBmsService.getSoHGraphData(carId);

		return ResponseEntity.ok(sohGraphDatas);
	}


	@ApiOperation(value = "배터리 예측 (AI) 데이터 조회")
	@GetMapping("/cars/{carId}/ai")
	public ResponseEntity<Object> getPredictData(@PathVariable Long carId) {

		UserBmsPredictDto userBmsPredictDto = userBmsService.getPredictData(carId);

		return ResponseEntity.ok(userBmsPredictDto);
	}


	@ApiOperation(value = "친환경 데이터 조회")
	@GetMapping("/echo")
	public ResponseEntity<Object> getEchoData() {

		String accountId = securityService.getUser().getId();

		BmsEchoDto bmsEchoDto = userBmsService.getEchoData(accountId);

		return ResponseEntity.ok(bmsEchoDto);
	}
}
