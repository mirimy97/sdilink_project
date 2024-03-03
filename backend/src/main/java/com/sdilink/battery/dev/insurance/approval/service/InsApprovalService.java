package com.sdilink.battery.dev.insurance.approval.service;

import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.dev.bms.dto.InsuranceModuleLogDto;
import com.sdilink.battery.dev.bms.dto.ModuleLogDto;
import com.sdilink.battery.dev.bms.dto.PackLogDto;
import com.sdilink.battery.dev.bms.repository.CellLogRepository;
import com.sdilink.battery.dev.bms.repository.ModuleLogRepository;
import com.sdilink.battery.dev.bms.repository.PackLogRepository;
import com.sdilink.battery.dev.bmsAnalysis.dto.InsBmsAnalysisDto;
import com.sdilink.battery.dev.bmsAnalysis.repository.BmsAnalysisRepository;
import com.sdilink.battery.dev.car.dto.InsCarAndClientDto;
import com.sdilink.battery.dev.expoToken.service.ExpoTokenService;
import com.sdilink.battery.dev.viewHistory.dto.ViewHistoryRecentDto;
import com.sdilink.battery.dev.viewHistory.repository.ViewHistoryRepository;
import com.sdilink.battery.domain.*;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;

import java.time.LocalDateTime;

import io.github.jav.exposerversdk.PushClient;
import io.github.jav.exposerversdk.PushClientException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sdilink.battery.dev.approval.dto.ApprovalAcceptDto;
import com.sdilink.battery.dev.approval.dto.ApprovalRefuseDto;
import com.sdilink.battery.dev.approval.dto.ApprovalWaitDto;
import com.sdilink.battery.dev.approval.repository.ApprovalRepository;
import com.sdilink.battery.dev.car.repository.CarRepository;

import com.sdilink.battery.dev.insurance.user.repository.InsuranceRepository;

import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class InsApprovalService {

	private final InsuranceRepository insuranceRepository;
	private final ApprovalRepository approvalRepository;

	private final ViewHistoryRepository viewHistoryRepository;

	private final CarRepository carRepository;

	private final PackLogRepository packLogRepository;

	private final ModuleLogRepository moduleLogRepository;

	private final CellLogRepository cellLogRepository;

	private final BmsAnalysisRepository bmsAnalysisRepository;

	private final ExpoTokenService expoTokenService;


	public void calculateModuleLogOutlier(ModuleLog moduleLog) {
		// moduleLog.outlier 값 없을 때, 집계 시행

		List<CellLog> cellLogList = cellLogRepository.findAllByModuleLog(moduleLog);

		int count = 0;
		for (CellLog cellLog : cellLogList) {
			if (cellLog.getIsNormal() == -1) {
				count++;
			}
		}

		moduleLog.setOutlier(count);
		moduleLogRepository.save(moduleLog);
	}

	public ApprovalWaitDto requestApproval(String accountId, Long carId)  throws PushClientException {

		Insurance insurance = insuranceRepository.findInsuranceByAccountId(accountId).get();

		Optional<Car> optionalCar = carRepository.findById(carId);

		if(optionalCar.isEmpty()) {
			throw new CustomException(ErrorCode.NO_MATCH_CAR);
		}

		Car car = optionalCar.get();

		if(!car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_MATCH_CAR);
		}

		Optional<Approval> optionalApproval = approvalRepository.findTopByInsuranceAndCarAndIsApproveOrderByIdDesc(insurance, car, 0);

		if(optionalApproval.isPresent() && optionalApproval.get().getCreatedAt().isAfter(LocalDateTime.now().minusDays(3))) {
			throw new CustomException(ErrorCode.APPROVAL_DENIED);
		}

		Approval approval = Approval.builder()
				.car(car)
				.insurance(insurance)
				.build();

		//요청 저장
		Approval approval1 = approvalRepository.save(approval);

		ApprovalWaitDto approvalWaitDto = ApprovalWaitDto.builder()
				.id(approval1.getId())
				.insuranceName(insurance.getName())
				.userName(car.getUser().getName())
				.carNumber(car.getCarNumber())
				.createdAt(approval1.getCreatedAt())
				.build();

		// 푸시 알림
		String recipient = expoTokenService.getTokenByUser(car.getUser());

		if (PushClient.isExponentPushToken(recipient)) {
			String title = "🔔 SDILink";
			String message = approvalWaitDto.getInsuranceName() + "에서 차량번호" + approvalWaitDto.getCarNumber() + "에 대한 배터리 정보 열람 승인 요청을 보냈어요!";
			expoTokenService.sendExpoPushMessage(recipient, title, message);
		}

		return approvalWaitDto;
	}

	public Map<String, Object> getApprovals(String accountId) {

		Insurance insurance = insuranceRepository.findInsuranceByAccountId(accountId).get();

		LocalDateTime authTime = LocalDateTime.now().minusDays(15);

		Map<String, Object> map = new HashMap<>();
		List<Approval> approvalList = approvalRepository.findAllByInsurance(insurance.getId(), authTime);

		List<ApprovalWaitDto> approvalWaitDtoList = new ArrayList<>();
		List<ApprovalAcceptDto> approvalAcceptDtoList = new ArrayList<>();
		List<ApprovalRefuseDto> approvalRefuseDtoList = new ArrayList<>();

		for(Approval approval : approvalList) {
			switch (approval.getIsApprove()){
				case 0:
					//승인대기
					ApprovalWaitDto approvalWaitDto = ApprovalWaitDto.builder()
							.id(approval.getId())
							.insuranceName(approval.getInsurance().getName())
							.userName(approval.getCar().getUser().getName())
							.carId(approval.getCar().getId())
							.carNumber(approval.getCar().getCarNumber())
							.createdAt(approval.getCreatedAt())
							.build();
					approvalWaitDtoList.add(approvalWaitDto);
					break;
				case 1:
					//승인완료
					ApprovalAcceptDto approvalAcceptDto = ApprovalAcceptDto.builder()
							.id(approval.getId())
							.insuranceName(approval.getInsurance().getName())
							.userName(approval.getCar().getUser().getName())
							.carId((approval.getCar().getId()))
							.carNumber(approval.getCar().getCarNumber())
							.createdAt(approval.getCreatedAt())
							.authTime(approval.getAuthTime())
							.endTime(approval.getAuthTime().plusDays(15))
							.leftDay(ChronoUnit.DAYS.between(LocalDateTime.now(), approval.getAuthTime().plusDays(15)))
							.build();
					approvalAcceptDtoList.add(approvalAcceptDto);
					break;
				case 2:
					ApprovalRefuseDto approvalRefuseDto = ApprovalRefuseDto.builder()
							.id(approval.getId())
							.insuranceName(approval.getInsurance().getName())
							.userName(approval.getCar().getUser().getName())
							.carId(approval.getCar().getId())
							.carNumber(approval.getCar().getCarNumber())
							.createdAt(approval.getCreatedAt())
							.refuseTime(approval.getAuthTime())
							.build();
					approvalRefuseDtoList.add(approvalRefuseDto);
					break;
				default:
					break;
			}
		}
		map.put("accept", approvalAcceptDtoList);
		map.put("waiting", approvalWaitDtoList);
		map.put("refuse", approvalRefuseDtoList);

		return map;
	}

	/* 보험사가 최근 조회한 고객 & 차량 정보 & 조회 정보 */
	public List<ViewHistoryRecentDto> getRecentViewHistories(String accountId) {

//		보험사 검색
		Insurance insurance = insuranceRepository.findInsuranceByAccountId(accountId)
				.orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_USER));

		// 최근 조회한 10개 추출
		List<ViewHistory> recentViewHistoryList = viewHistoryRepository.findFirst10ByInsuranceOrderByCreatedAtDesc(insurance);

		if (recentViewHistoryList.isEmpty()) {
			return Collections.emptyList();
		}

		List<ViewHistoryRecentDto> dataList = new ArrayList<>();

		for (ViewHistory viewHistory : recentViewHistoryList) {
			// 해당 조회내역에 대한 최근 승인건 조회
			Approval latestApproval = approvalRepository.findFirstByInsuranceAndCarAndIsApproveOrderByAuthTimeDesc(insurance, viewHistory.getCar(), 1);
			// approval 없으면 무시
			if (latestApproval == null) {
				continue;
			}

			Boolean isExpired = false;
			if (latestApproval.getAuthTime().isBefore(LocalDateTime.now().minusDays(15))) {
				// 승인건의 Auth Time이 현재 시간에서 15일 전인 경우
				isExpired = true;
			}
			ViewHistoryRecentDto viewHistoryRecentDto = ViewHistoryRecentDto.builder()
					.viewHistoryId(viewHistory.getId())
					.approvalId(latestApproval.getId())
					.isExpired(isExpired)
					.carId(viewHistory.getCar().getId())
					.name(viewHistory.getCar().getUser().getName())
					.carInfoId(viewHistory.getCar().getCarInfo().getId())
					.modelName(viewHistory.getCar().getCarInfo().getModelName())
					.packCode(viewHistory.getCar().getPackCode())
					.createdAt(viewHistory.getCreatedAt())
					.build();

			dataList.add(viewHistoryRecentDto);
		}

		return dataList;
	}

	public Object getBmsLog(String accountId, Long approvalId, LocalDateTime dateTime) {
		Approval approval = getApprovalById(approvalId, accountId);

		if(dateTime != null) {
			return getBmsByDate(approval.getCar(), dateTime);
		}

		return new ArrayList<>();
	}

	private List<InsuranceModuleLogDto> getBmsByDate(Car car, LocalDateTime dateTime) {
		// 주행중 데이터만
		Optional<PackLog> optionalPackLog = packLogRepository.findByCarAndCreatedAtAndStatus(car, dateTime, 2);

		if(optionalPackLog.isEmpty()) return null;

		PackLog packLog = optionalPackLog.get();

		List<ModuleLog> moduleLogList = moduleLogRepository.findAllByPackLog(packLog);

		List<InsuranceModuleLogDto> moduleLogDtoList = new ArrayList<>();


		for(ModuleLog moduleLog: moduleLogList) {

			if(moduleLog.getOutlier() == null) {
				// moduleLog.outlier 값 없을 때, 집계 시행
				calculateModuleLogOutlier(moduleLog);
			}

			List<CellLog> cellLogList = cellLogRepository.findAllByModuleLog(moduleLog);
			List<CellLogDto> cellLogDtoList = new ArrayList<>();

			for(CellLog cellLog: cellLogList) {
				cellLogDtoList.add(CellLogDto.builder()
						.id(cellLog.getId())
						.cellCode(cellLog.getCellCode())
						.voltageC(cellLog.getVoltageC())
						.createdAt(cellLog.getCreatedAt())
						.isNormal(cellLog.getIsNormal())
						.outlier(cellLog.getOutlier()) //수정 필요
						.build());
			}

			moduleLogDtoList.add(InsuranceModuleLogDto.builder()
					.id(moduleLog.getId())
					.moduleCode(moduleLog.getModuleCode())
					.temp(moduleLog.getTempM())
					.voltage(moduleLog.getVoltageM())
					.cellLogList(cellLogDtoList)
					.build());

		}

		return moduleLogDtoList;
	}


	/* 보험사 측에서 고객의 차량 id로 차량 및 고객 정보 조회 */
	public InsCarAndClientDto getClientCarDetail(String accountId, Long approvalId) throws PushClientException {


//		Approval 유효성 검증
		Approval approval = getApprovalById(approvalId, accountId);
		Long carId = approval.getCar().getId();

//		조회 이력 저장
		Insurance insurance = insuranceRepository.findInsuranceByAccountId(accountId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));

		viewHistoryRepository.save(new ViewHistory().builder()
				.insurance(insurance)
				.car(approval.getCar())
				.build());

//		 조회 푸시 알림
		String recipient = expoTokenService.getTokenByUser(approval.getCar().getUser());

		if (PushClient.isExponentPushToken(recipient)) {
			String title = "🔎 SDILink";
			String message = insurance.getName() + "에서 차량번호" + approval.getCar().getCarNumber() + "의 배터리 정보를 열람했습니다!";
			System.out.println("push notification result = "
					+ expoTokenService.sendExpoPushMessage(recipient, title, message));

		}


		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));

		InsCarAndClientDto insCarAndClientDto = InsCarAndClientDto.builder()
				.name(car.getUser().getName())
				.birth(car.getUser().getBirth())
				.carInfoId(car.getCarInfo().getId())
				.modelName(car.getCarInfo().getModelName())
				.carNumber(car.getCarNumber())
				.packCode(car.getPackCode())
				.build();

		return insCarAndClientDto;
	}

	//    보험사 측에서 고객 차량 id로 차량의 analysis 정보 조회
	public InsBmsAnalysisDto getClientCarAnalysis(String accountId, Long approvalId) {

		//		Approval 유효성 검증
		Approval approval = getApprovalById(approvalId, accountId);
		Long carId = approval.getCar().getId();

		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));

		BmsAnalysis bmsAnalysis = bmsAnalysisRepository.findTopByCarOrderByIdDesc(car)
				.orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_ENTITY));

		InsBmsAnalysisDto insBmsAnalysisDto = InsBmsAnalysisDto.builder()
				.fastCharge(bmsAnalysis.getFastCharge())
				.slowCharge(bmsAnalysis.getSlowCharge())
				.totalRuntime(bmsAnalysis.getTotalRuntime())
				.totalCycle(bmsAnalysis.getTotalCycle())
				.totalCharge(bmsAnalysis.getTotalCharge())
				.totalDischarge(bmsAnalysis.getTotalDischarge())
				.bLeftCycle(bmsAnalysis.getBLeftCycle())
				.totalDrive(bmsAnalysis.getTotalDrive())
				.bTotalScore(bmsAnalysis.getBTotalScore())
				.build();

		return insBmsAnalysisDto;
	}

	// pack - module - log 일련번호 조회
	public Map<String, List<String>> getPackStructure(String accountId, Long approvalId) {

		//		Approval 유효성 검증, 승인 객체에 해당하는 car 가져오기
		Approval approval = getApprovalById(approvalId, accountId);
		Car car = approval.getCar();

//		해당 car의 최상단 PackLog 가져오기
		Optional<PackLog> recentPackLog = packLogRepository.findTopByCarOrderByIdDesc(car);

		if(recentPackLog.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

//		packLog id로 해당하는 module Log 찾기
		List<ModuleLog> moduleLogs = moduleLogRepository.findAllByPackLog(recentPackLog.get());

//		moduleLog 없으면 ??

//		pack 구조 생성

		Map<String, List<String>> packStructure = new HashMap<>();

		for (ModuleLog moduleLog : moduleLogs) {
			List<CellLog> cellLogs = cellLogRepository.findAllByModuleLog(moduleLog);
			List<String> cellCodes = new ArrayList<>();
			for (CellLog cellLog : cellLogs) {
				cellCodes.add(cellLog.getCellCode());
			}
			packStructure.put(moduleLog.getModuleCode(), cellCodes);
		}

		return packStructure;
	}


	// module raw data 조회
	public List<PackLogDto> getPackLogsByDate(Long approvalId, String accountId, LocalDateTime startTime, LocalDateTime endTime) {

		Approval approval = getApprovalById(approvalId, accountId);

		List<PackLog> packLogList = packLogRepository.findAllByCarAndCreatedAtBetween(approval.getCar(), startTime, endTime);

		List<PackLogDto> packLogDtoList = new ArrayList<>();

		for(PackLog packLog: packLogList) {

			packLogDtoList.add(PackLogDto.builder()
					.id(packLog.getId())
					.packCode(packLog.getPackCode())
					.voltageP(packLog.getVoltageP())
					.current(packLog.getCurrent())
					.tempP(packLog.getTempP())
					.status(packLog.getStatus()==1?"충전중":(packLog.getStatus()==2?"주행중":"전원꺼짐"))
					.capacity(packLog.getCapacity())
					.soc(packLog.getSoc())
					.soh(packLog.getSoh())
					.cycle(packLog.getCycle())
					.createdAt(packLog.getCreatedAt())
					.build());
		}

		return packLogDtoList;
	}

	//module raw data 조회
	public List<ModuleLogDto> getModuleLogsByDate(Long approvalId, String accountId, String moduleCode, LocalDateTime startTime, LocalDateTime endTime) {
		Approval approval = getApprovalById(approvalId, accountId);

		List<ModuleLogDto> moduleLogDtoList = new ArrayList<>();

		List<ModuleLog> moduleLogList = moduleLogRepository.findAllByModuleCodeAndCreatedAtBetween(moduleCode, startTime, endTime);

		//수정 필요. (비효율적임)
		if(moduleLogList.size() != 0 && moduleLogList.get(0).getPackLog().getCar().getId() != approval.getCar().getId()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		for(ModuleLog moduleLog : moduleLogList) {

			if(moduleLog.getOutlier() == null) {
				// moduleLog.outlier 값 없을 때, 집계 시행
				calculateModuleLogOutlier(moduleLog);
			}

			moduleLogDtoList.add(ModuleLogDto.builder()
					.id(moduleLog.getId())
					.moduleCode(moduleLog.getModuleCode())
					.temp(moduleLog.getTempM())
					.voltage(moduleLog.getVoltageM())
					.outlier(moduleLog.getOutlier())
					.createdAt(moduleLog.getCreatedAt())
					.build());
		}

		return moduleLogDtoList;
	}

	public List<CellLogDto> getCellLogsByDate(Long approvalId, String accountId, String cellCode, LocalDateTime startTime, LocalDateTime endTime) {

		Approval approval = getApprovalById(approvalId, accountId);

		List<CellLog> cellLogList = cellLogRepository.findAllByCellCodeAndCreatedAtBetween(cellCode, startTime, endTime);


		//수정 필요. (비효율적임)
		if(cellLogList.size() != 0 && cellLogList.get(0).getModuleLog().getPackLog().getCar().getId() != approval.getCar().getId()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		List<CellLogDto> cellLogDtoList = cellLogRepository.findAllByCellCodeAndCreatedAtBetween(cellCode, startTime, endTime)
				.stream()
				.map(cellLog -> CellLogDto.builder()
						.id(cellLog.getId())
						.cellCode(cellLog.getCellCode())
						.voltageC(cellLog.getVoltageC())
						.outlier(cellLog.getOutlier())
						.isNormal(cellLog.getIsNormal())
						.createdAt(cellLog.getCreatedAt())
						.build())
				.collect(Collectors.toList());
		return cellLogDtoList;
	}

	//조회 가능한 승인 요청인지 확인
	private Approval getApprovalById(Long approvalId, String accountId) {
		Optional<Approval> optionalApproval = approvalRepository.findById(approvalId);
		LocalDateTime authTime = LocalDateTime.now().minusDays(15);

		if(optionalApproval.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

		Approval approval = optionalApproval.get();

		if(!approval.getInsurance().getAccountId().equals(accountId)) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		if(approval.getIsApprove()==1 && approval.getAuthTime() != null && approval.getAuthTime().isAfter(authTime)) {
			return approval;
		} else {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}
	}


	// SoH 그래프 데이터 조회 (첫 cycle ~ 최근 cycle)
	public List<Map<String, Object>> getSohGraphData(String accountId, Long approvalId) {

		Approval approval = getApprovalById(approvalId, accountId);

		Car car = approval.getCar();

		//		PackLog의 주행중인 가장 최신 cycle 조회
		PackLog lastPackLog = packLogRepository.findTopByCarAndStatusOrderByIdDesc(car, 2)
				.orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_ENTITY));
		Integer lastCycle = lastPackLog.getCycle();

//		그래프 데이터 List 생성
		List<Map<String, Object>> dataList = new ArrayList<>();

		for (int i = 1; i <= lastCycle; i++) {
			PackLog latestPackLogInCycle = packLogRepository.findFirstByCycleAndStatusOrderByIdDesc(i, 2);

			if (latestPackLogInCycle != null) {
				Map<String, Object> map = new HashMap<>();
				map.put("name", i);
				map.put("SOH", latestPackLogInCycle.getSoh());

				dataList.add(map);
			}
		}

		return dataList;
	}

	// 전압, 전류, 온도 그래프 데이터 조회  (최근 ~ 이전 3시간)
	public List<Map<String, Object>> getGraphData(String accountId, Long approvalId) {

		Approval approval = getApprovalById(approvalId, accountId);

		Car car = approval.getCar();

		if (!car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		//LocalDateTime endTime = LocalDateTime.now();
		//LocalDateTime startTime = endTime.minusHours(3);

		List<PackLog> packLogList = packLogRepository.findTop180ByCarOrderByIdDesc(car);

		Collections.reverse(packLogList);

//		List<PackLog> packLogList = packLogRepository.findAllByCarAndStatusAndCreatedAtBetween(car, 2, startTime, endTime);

		if (packLogList.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

		List<Map<String, Object>> dataList = new ArrayList<>();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

		for (PackLog packLog : packLogList) {

			Map<String, Object> map = new HashMap<>();
			map.put("name", packLog.getCreatedAt().format(formatter));
			map.put("voltageP", packLog.getVoltageP());
			map.put("current", packLog.getCurrent());
			map.put("tempP", packLog.getTempP());

			dataList.add(map);
		}

		return dataList;
	}
}
