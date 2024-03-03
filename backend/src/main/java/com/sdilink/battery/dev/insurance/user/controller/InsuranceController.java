package com.sdilink.battery.dev.insurance.user.controller;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sdilink.battery.dev.bms.dto.BmsJsonDto;
import com.sdilink.battery.dev.car.dto.CarSerachDto;
import com.sdilink.battery.dev.insurance.user.dto.ApiTokenDto;
import com.sdilink.battery.dev.insurance.user.service.ApiTokenService;
import com.sdilink.battery.dev.insurance.user.service.InsuranceService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sdilink.battery.dev.insurance.user.dto.InsuranceDto;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.jwt.JwtProvider;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.security.SecurityService;

import lombok.RequiredArgsConstructor;

import javax.annotation.Resource;

@RequiredArgsConstructor
@RestController
@RequestMapping("/insurance")
@Api(tags = {"보험사"})
public class InsuranceController {

	private final InsuranceService insuranceService;

	private final ApiTokenService apiTokenService;

	private final SecurityService securityService;

	private final JwtProvider jwtProvider;

	@ApiOperation(value = "보험사 로그인")
	@PostMapping("/login")
	public ResponseEntity<?> loginSuccess(@RequestBody Map<String, String> loginForm)  {
		Map<String , Object> info = insuranceService.login(loginForm.get("id"), loginForm.get("password"));
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", (String) info.get("accessToken"));

		return ResponseEntity.ok()
			.headers(headers)
			.body(info.get("insurance"));

	}

	//test 용 join
//	@PostMapping("/join")
//	public ResponseEntity<?> join(@RequestBody Map<String, String> joinForm) {
//		insuranceService.addInsurance(joinForm.get("username"), joinForm.get("password"), joinForm.get("name"));
//
//		return  ResponseEntity.status(HttpStatus.CREATED).body(joinForm);
//	}

	@ApiOperation(value = "보험사 개인정보 조회")
	@GetMapping("/{id}")
	public ResponseEntity<?> getInsurance(@PathVariable("id") String id) {

		InsuranceDto insuranceDto = insuranceService.getInsurance(id);
		return ResponseEntity.status(HttpStatus.OK).body(insuranceDto);
	}

	@ApiOperation(value = "고객 정보 검색")
	@PostMapping("/search")
	public ResponseEntity<?> getUserInfo(@RequestBody CarSerachDto carSearchDto) throws Exception {

		CarSerachDto carSerachDto1 = insuranceService.getUserInfo(carSearchDto);
		return ResponseEntity.status(HttpStatus.OK).body(carSerachDto1);
	}

	@ApiOperation(value = "API 토큰 발급")
	//api token 발급/재발급
	@PostMapping("/api/token")
	public ResponseEntity<?> createApiToken() {
		AuthDto authDto = securityService.getUser();

		Map<String, String> result = apiTokenService.createApiToken(authDto.getId());
		return ResponseEntity.ok(result);
	}

	//token 조회
	@ApiOperation(value = "API token 조회")
	@GetMapping("/api/token")
	public ResponseEntity<?> getApiToken() {
		AuthDto authDto = securityService.getUser();

		ApiTokenDto apiTokenDto = apiTokenService.getApiToken(authDto.getId());
		return ResponseEntity.ok(apiTokenDto);
	}

	//token 삭제
	@ApiOperation(value = "API 토큰 삭제")
	@DeleteMapping("/api/token")
	public ResponseEntity<?> deleteApiToken() {
		AuthDto authDto = securityService.getUser();

		Map<String, Object> result = new HashMap<>();

		apiTokenService.deleteApiToken(authDto.getId());

		result.put("message", "토큰이 삭제되었습니다.");

		return ResponseEntity.ok(result);
	}

	@GetMapping("/api/bms")
	public ResponseEntity<?> getBmsJsonData( @RequestParam("apiToken") String apiToken,
		@RequestParam("startTime") String startTimeStr,
		@RequestParam("endTime") String endTimeStr,
		@RequestParam("carNumber") String carNumber) {

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

		List<BmsJsonDto> bmsJsonDtoList = apiTokenService.getBmsJsonData(apiToken, startTime, endTime, carNumber);

		return ResponseEntity.ok(bmsJsonDtoList);
	}



	// CSV 데이터 다운로드 (보류)
	@GetMapping("/api/download")
	public ResponseEntity<ByteArrayResource> downloadFileTest() {

		// 파일 데이터 생성
		String data = "가, 나, 다, \n 1, 2, 3";

		// 파일 이름 설정
		String filename = "testyoyoyo.csv";

		// Resource 객체로 파일 데이터와 파일 이름 설정
		ByteArrayResource resource = new ByteArrayResource(data.getBytes());

		// HTTP Header 설정
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename);
		headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE);

		// ResponseEntity 생성
		return ResponseEntity.ok()
				.headers(headers)
				.contentLength(resource.contentLength())
				.body(resource);
	}
}
