package com.sdilink.battery.dev.insurance.approval.controller;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.dev.bmsAnalysis.dto.InsBmsAnalysisDto;
import com.sdilink.battery.dev.car.dto.InsCarAndClientDto;
import com.sdilink.battery.dev.bms.dto.ModuleLogDto;
import com.sdilink.battery.dev.bms.dto.PackLogDto;

import com.sdilink.battery.dev.expoToken.service.ExpoTokenService;
import com.sdilink.battery.dev.viewHistory.dto.ViewHistoryRecentDto;
import io.github.jav.exposerversdk.PushClientException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sdilink.battery.dev.approval.dto.ApprovalWaitDto;
import com.sdilink.battery.dev.insurance.approval.service.InsApprovalService;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.security.SecurityService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/insurance/approvals")
@Api(tags = {"보험사 승인 요청"})
public class InsuranceApprovalController {
	private final InsApprovalService insApprovalService;

	private final SecurityService securityService;

	@ApiOperation(value = "자동차 정보 조회 승인 요청")
	@PostMapping("/cars/{carId}")
	public ResponseEntity<?> requestApproval(@PathVariable(value = "carId", required = true) Long carId)  throws PushClientException {
		AuthDto authDto = securityService.getUser();

		ApprovalWaitDto approvalWaitDto = insApprovalService.requestApproval(authDto.getId(), carId);

		return ResponseEntity.status(HttpStatus.OK).body(approvalWaitDto);
	}

	@ApiOperation(value = "승인 요청 목록 읽어오기")
	@GetMapping("")
	public ResponseEntity<?> getApprovals() {
		AuthDto authDto = securityService.getUser();

		Map<String, Object> approvals = insApprovalService.getApprovals(authDto.getId());
		return ResponseEntity.status(HttpStatus.OK).body(approvals);
	}

	@ApiOperation(value = "특정 시간의 bms 정보 조회")
	@GetMapping("/{approvalId}/bms")
	public ResponseEntity<?> getBmsLog (@PathVariable(value = "approvalId", required = true) Long approvalId, @RequestParam("time")
		String time) {

		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		LocalDateTime dateTime = null;

		try {
			dateTime = LocalDateTime.parse(time, formatter);
		}
		catch (Exception e) {
			throw new CustomException(ErrorCode.REQUEST_PARAMETER);
		}

		AuthDto authDto = securityService.getUser();

		List<Object> lists = (List<Object>)insApprovalService.getBmsLog(authDto.getId(), approvalId, dateTime);
		return ResponseEntity.status(HttpStatus.OK).body(lists);
	}

	/* 보험사가 최근 조회한 고객 & 차량 정보 & 조회 정보 */
	@ApiOperation(value = "최근 조회한 고객 정보 가져오기")
	@GetMapping("/histories")
	public ResponseEntity<Object> getRecentViewHistories() {

		AuthDto authDto = securityService.getUser();

		List<ViewHistoryRecentDto> recentViewHistoryList = insApprovalService.getRecentViewHistories(authDto.getId());
		return ResponseEntity.ok(recentViewHistoryList);

	}

	@ApiOperation(value = "보험사 - 고객 및 차량 상세 정보 조회")
	@GetMapping("/{approvalId}/detail")
	public ResponseEntity<Object> getClientCarDetail(@PathVariable Long approvalId) throws PushClientException {

		AuthDto authDto = securityService.getUser();

		InsCarAndClientDto insCarAndClientDto = insApprovalService.getClientCarDetail(authDto.getId(), approvalId);


		return ResponseEntity.ok(insCarAndClientDto);
	}

	@ApiOperation(value = "보험사 - 고객 차량 통계 및 예측 정보 조회")
	@GetMapping("/{approvalId}/analysis")
	public ResponseEntity<Object> getClientCarAnalysis(@PathVariable Long approvalId) {

		AuthDto authDto = securityService.getUser();

		InsBmsAnalysisDto insBmsAnalysisDto = insApprovalService.getClientCarAnalysis(authDto.getId(), approvalId);

		return ResponseEntity.ok(insBmsAnalysisDto);
	}

	@ApiOperation(value = "pack-module-cell 일련번호 조회")
	@GetMapping("/{approvalId}/bms/codes")
	public ResponseEntity<?> getPackStructure(@PathVariable Long approvalId) {

		AuthDto authDto = securityService.getUser();

		Map<String, List<String>> packStructure = insApprovalService.getPackStructure(authDto.getId(), approvalId);

		return ResponseEntity.ok(packStructure);
	}


	@ApiOperation(value = "pack raw data 조회")
	@GetMapping("/{approvalId}/bms/packs")
	public ResponseEntity<Object> getPackLogs(@PathVariable(value = "approvalId", required = true) Long approvalId,
		@RequestParam("startTime") String startTimeStr,
		@RequestParam("endTime") String endTimeStr ) {

		AuthDto authDto = securityService.getUser();

		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
		LocalDateTime startTime = null;
		LocalDateTime endTime = null;

		try {
			startTime = LocalDateTime.parse(startTimeStr, formatter);
			endTime = LocalDateTime.parse(endTimeStr, formatter);
		}
		catch (Exception e) {
			throw new CustomException(ErrorCode.REQUEST_PARAMETER);
		}

		Map<String, Object> result = new HashMap<>();
		List<PackLogDto> packLogDtoList = insApprovalService.getPackLogsByDate(approvalId, authDto.getId(), startTime, endTime);
		result.put("packList", packLogDtoList);

		return ResponseEntity.ok(result);

	}

	@ApiOperation(value = "module raw data 조회")
	@GetMapping("/{approvalId}/bms/modules")
	public ResponseEntity<Object> getModuleLogs(@PathVariable(value = "approvalId", required = true) Long approvalId,
		@RequestParam("moduleCode") String moduleCode,
		@RequestParam("startTime") String startTimeStr,
		@RequestParam("endTime") String endTimeStr ) {

		AuthDto authDto = securityService.getUser();

		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
		LocalDateTime startTime = null;
		LocalDateTime endTime = null;

		try {
			startTime = LocalDateTime.parse(startTimeStr, formatter);
			endTime = LocalDateTime.parse(endTimeStr, formatter);
		}
		catch (Exception e) {
			throw new CustomException(ErrorCode.REQUEST_PARAMETER);
		}


		Map<String, Object> result = new HashMap<>();
		List<ModuleLogDto> moduleLogDtoList = insApprovalService.getModuleLogsByDate(approvalId, authDto.getId(), moduleCode, startTime, endTime);
		result.put("moduleList", moduleLogDtoList);

		return ResponseEntity.ok(result);
	}

	@ApiOperation(value = "cell raw data 조회")
	@GetMapping("/{approvalId}/bms/cells")
	public ResponseEntity<Object> getCellLogs(@PathVariable(value = "approvalId", required = true) Long approvalId,
		@RequestParam("cellCode") String cellCode,
		@RequestParam("startTime") String startTimeStr,
		@RequestParam("endTime") String endTimeStr ) {

		AuthDto authDto = securityService.getUser();

		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
		LocalDateTime startTime = null;
		LocalDateTime endTime = null;

		try {
			startTime = LocalDateTime.parse(startTimeStr, formatter);
			endTime = LocalDateTime.parse(endTimeStr, formatter);
		}
		catch (Exception e) {
			throw new CustomException(ErrorCode.REQUEST_PARAMETER);
		}


		Map<String, Object> result = new HashMap<>();
		List<CellLogDto> moduleLogDtoList = insApprovalService.getCellLogsByDate(approvalId, authDto.getId(), cellCode, startTime, endTime);
		result.put("cellList", moduleLogDtoList);

		return ResponseEntity.ok(result);
	}

	@ApiOperation(value = "SoH 그래프 데이터")
	@GetMapping("/{approvalId}/bms/sohgraph")
	public ResponseEntity<Object> getSohGraphData(@PathVariable Long approvalId) {

		AuthDto authDto = securityService.getUser();

		List<Map<String, Object>> sohGraphDatas = insApprovalService.getSohGraphData(authDto.getId(), approvalId);

		return ResponseEntity.ok(sohGraphDatas);
	}

	@ApiOperation(value = "전압, 전류, 온도 그래프 데이터")
	@GetMapping("/{approvalId}/bms/graph")
	public ResponseEntity<Object> getGraphData(@PathVariable Long approvalId) {

		AuthDto authDto = securityService.getUser();

		List<Map<String, Object>> graphDatas = insApprovalService.getGraphData(authDto.getId(), approvalId);

		return ResponseEntity.ok(graphDatas);
	}

}
