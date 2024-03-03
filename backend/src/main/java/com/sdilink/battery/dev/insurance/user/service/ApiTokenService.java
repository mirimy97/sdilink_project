package com.sdilink.battery.dev.insurance.user.service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sdilink.battery.dev.approval.repository.ApprovalRepository;
import com.sdilink.battery.dev.bms.dto.BmsJsonDto;
import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.dev.bms.dto.InsuranceModuleLogDto;
import com.sdilink.battery.dev.bms.repository.CellLogRepository;
import com.sdilink.battery.dev.bms.repository.ModuleLogRepository;
import com.sdilink.battery.dev.bms.repository.PackLogRepository;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.insurance.user.dto.ApiTokenDto;
import com.sdilink.battery.dev.insurance.user.repository.InsuranceRepository;
import com.sdilink.battery.domain.Approval;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.CellLog;
import com.sdilink.battery.domain.Insurance;
import com.sdilink.battery.domain.ModuleLog;
import com.sdilink.battery.domain.PackLog;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.jwt.JwtProvider;

import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class ApiTokenService {

	private final JwtProvider jwtProvider;
	private final InsuranceRepository insuranceRepository;

	private final CarRepository carRepository;

	private final ApprovalRepository approvalRepository;

	private final PackLogRepository packLogRepository;

	private final ModuleLogRepository moduleLogRepository;

	private final CellLogRepository cellLogRepository;

	public Map<String, String> createApiToken(String accountId) {

		Insurance insurance = getInsuranceByAccountId(accountId);

		String apiToken = jwtProvider.createApiToken(accountId);

		insurance.setApiToken(apiToken);

		Map<String, String> result = new HashMap<>();
		result.put("apiToken", apiToken);

		return result;
	}

	public ApiTokenDto getApiToken(String accountId) {

		Insurance insurance = getInsuranceByAccountId(accountId);

		if(insurance.getApiToken() == null || insurance.getTokenDate() == null) {
			throw new CustomException(ErrorCode.NOT_FOUND_API_TOKEN);
		}

		ApiTokenDto apiTokenDto = ApiTokenDto.builder()
			.apiToken(insurance.getApiToken())
			.createdAt(insurance.getTokenDate())
			.expiredAt(insurance.getTokenDate().plusDays(30))
			.leftDate(Long.valueOf(ChronoUnit.DAYS.between(LocalDateTime.now(), insurance.getTokenDate().plusDays(30))).intValue())
			.build();
		return apiTokenDto;
	}

	public void deleteApiToken(String accountId) {

		Insurance insurance = getInsuranceByAccountId(accountId);
		boolean result = insurance.deleteApiToken();

		if(!result) {
			throw new CustomException(ErrorCode.NOT_FOUND_API_TOKEN);
		}
	}

	private Insurance getInsuranceByAccountId(String accountId) {
		Optional<Insurance> optionalInsurance = insuranceRepository.findInsuranceByAccountId(accountId);

		if(optionalInsurance.isEmpty()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}
		return optionalInsurance.get();
	}

	public List<BmsJsonDto> getBmsJsonData(String apiToken, LocalDateTime startTime, LocalDateTime endTime, String carNumber) {
		if(apiToken != null) {
			if(jwtProvider.verifyToken(apiToken)) {
				//token 으로 id 읽어오기
				String role = jwtProvider.getValue(apiToken, "role");

				if("API".equals(role)) {
					Optional<Car> optionalCar = carRepository.findCarByCarNumber(carNumber);

					if(optionalCar.isEmpty()) throw new CustomException(ErrorCode.NO_MATCH_CAR);

					Car car = optionalCar.get();

					List<Approval> approvalList = approvalRepository.findLatestApprovalByCar(car, LocalDateTime.now());

					if(approvalList.isEmpty()) {
						throw new CustomException(ErrorCode.NO_AUTHORITY);
					}

					return getBmsData(car, startTime, endTime);

				}
				else {
					throw new CustomException(ErrorCode.NOT_FOUND_API_TOKEN);
				}
			}
			else {
				throw new CustomException(ErrorCode.NOT_FOUND_API_TOKEN);
			}
		}
		else {
			throw new CustomException(ErrorCode.NOT_FOUND_API_TOKEN);
		}
	}

	public List<BmsJsonDto> getBmsData(Car car, LocalDateTime startTime, LocalDateTime endTime) {
		List<PackLog> packLogList = packLogRepository.findAllByCarAndCreatedAtBetween(car, startTime, endTime);
		List<BmsJsonDto> bmsJsonDtoList = new ArrayList<>();

		for(PackLog packLog: packLogList) {
			List<ModuleLog> moduleLogList = moduleLogRepository.findAllByPackLog(packLog);

			List<InsuranceModuleLogDto> insuranceModuleLogDtoList = new ArrayList<>();

			for (ModuleLog moduleLog: moduleLogList) {

				List<CellLogDto> cellLogDtoList = new ArrayList<>();
				List<CellLog> cellLogList = cellLogRepository.findAllByModuleLog(moduleLog);

				for(CellLog cellLog : cellLogList) {
					cellLogDtoList.add(CellLogDto.builder()
							.id(cellLog.getId())
							.cellCode(cellLog.getCellCode())
							.voltageC(cellLog.getVoltageC())
							.outlier(cellLog.getOutlier())
							.isNormal(cellLog.getIsNormal())
							.createdAt(cellLog.getCreatedAt())
						.build());
				}

				insuranceModuleLogDtoList.add(InsuranceModuleLogDto.builder()
						.id(moduleLog.getId())
						.moduleCode(moduleLog.getModuleCode())
						.temp(moduleLog.getTempM())
						.voltage(moduleLog.getVoltageM())
						.cellLogList(cellLogDtoList)
					.build());
			}

			bmsJsonDtoList.add(BmsJsonDto.builder()
					.id(packLog.getId())
					.packCode(packLog.getPackCode())
					.voltageP(packLog.getVoltageP())
					.current(packLog.getCurrent())
					.tempP(packLog.getTempP())
					.status(packLog.getStatus())
					.capacity(packLog.getCapacity())
					.soc(packLog.getSoc())
					.soh(packLog.getSoh())
					.cycle(packLog.getCycle())
					.createdAt(packLog.getCreatedAt())
					.moduleList(insuranceModuleLogDtoList)
				.build());
		}
		return 	bmsJsonDtoList;
	}
}
