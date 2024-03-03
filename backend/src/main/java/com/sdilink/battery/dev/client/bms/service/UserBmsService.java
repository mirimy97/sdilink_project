package com.sdilink.battery.dev.client.bms.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import com.sdilink.battery.dev.bms.dto.PackGraphDto;
import com.sdilink.battery.dev.bmsAnalysis.dto.BmsEchoDto;
import com.sdilink.battery.dev.bmsSoh.repository.BmsSohRepository;
import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.userbms.dto.UserBmsPredictDto;
import com.sdilink.battery.domain.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sdilink.battery.dev.bms.repository.CellLogRepository;
import com.sdilink.battery.dev.bms.repository.ModuleLogRepository;
import com.sdilink.battery.dev.bms.repository.PackLogRepository;
import com.sdilink.battery.dev.bmsAnalysis.repository.BmsAnalysisRepository;
import com.sdilink.battery.dev.userbms.dto.UserBmsDto;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.bms.dto.ModuleLogDto;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.security.SecurityService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class UserBmsService {

	private final UserRepository userRepository;
	private final CarRepository carRepository;
	private final PackLogRepository packLogRepository;

	private final ModuleLogRepository moduleLogRepository;

	private final CellLogRepository cellLogRepository;

	private final BmsAnalysisRepository bmsAnalysisRepository;

	private final BmsSohRepository bmsSohRepository;

	private final SecurityService securityService;


	@Scheduled(cron = "0 0 15 * * *")
	public void run() {
		System.out.println("--------------------- start calculate module log outlier ---------------------");

		LocalDateTime startTime = LocalDateTime.now().minusDays(1).withHour(15).withMinute(0).withSecond(0);
		LocalDateTime endTime = LocalDateTime.now().withHour(15).withMinute(0).withSecond(0);

		List<ModuleLog> moduleLogList = moduleLogRepository.findByCreatedAtBetween(startTime, endTime);

		for(ModuleLog moduleLog: moduleLogList) {

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

	}

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

	public UserBmsDto getBmsData(Long carId) {

		String accountId = securityService.getUser().getId();

//		Optional<Car> optionalCar = carRepository.findById(carId);
//
//		if(optionalCar.isEmpty()) {
//			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
//		}
//
//		Car car = optionalCar.get();

		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_ENTITY));

		//사용자의 차가 맞는지, 활성화 되어있는지 확인
		if(!car.getUser().getUserId().equals(accountId) || !car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		Optional<BmsAnalysis> optionalBmsAnalysis = bmsAnalysisRepository.findTopByCarOrderByIdDesc(car);

		Optional<PackLog> optionalPackLog = packLogRepository.findTopByCarAndStatusOrderByIdDesc(car, 2);


		if(optionalBmsAnalysis.isEmpty() || optionalPackLog.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

		BmsAnalysis bmsAnalysis = optionalBmsAnalysis.get();
		PackLog packLog = optionalPackLog.get();

		List<ModuleLogDto> moduleLogDtoList = new ArrayList<>();

		List<ModuleLog> moduleLogList = moduleLogRepository.findAllByPackLog(packLog);

		for(ModuleLog moduleLog: moduleLogList) {


			if(moduleLog.getOutlier() == null) {
				// moduleLog.outlier 값 없을 때, 집계 시행
				calculateModuleLogOutlier(moduleLog);
			}

			moduleLogDtoList.add(ModuleLogDto.builder()
					.id(moduleLog.getId())
					.moduleCode(moduleLog.getModuleCode())
					.temp(moduleLog.getTempM())
					.voltage(moduleLog.getVoltageM())
					.outlier(moduleLog.getOutlier()) //수정 필요
					.build());
		}

		UserBmsDto userBmsDto = UserBmsDto.builder()
				.bmsId(packLog.getId())
				.soc(packLog.getSoc())
				.voltage(packLog.getVoltageP())
				.temp(packLog.getTempP())
				.current(packLog.getCurrent())
				.bTotalScore(bmsAnalysis.getBTotalScore())
				.totalCharge(bmsAnalysis.getTotalCharge())
				.totalDischarge(bmsAnalysis.getTotalDischarge())
				.fastCharge(bmsAnalysis.getFastCharge())
				.totalRuntime(bmsAnalysis.getTotalRuntime()/(60*60))
				.createdAt(packLog.getCreatedAt())
				.modules(moduleLogDtoList)
				.build();

		return userBmsDto;
	}

	//bms pack 전압, 전류, 온도 graph data 조회
    public List<PackGraphDto> getBmsGraphData(Long carId) {
		String accountId = securityService.getUser().getId();

		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));


		//사용자의 차가 맞는지, 활성화 되어있는지 확인
		if(!car.getUser().getUserId().equals(accountId) || !car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}


		List<PackLog> packLogList = packLogRepository.findTop180ByCarOrderByIdDesc(car);

		if (packLogList.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

		Collections.reverse(packLogList);

		List<PackGraphDto> packGraphDtoList = new ArrayList<>();

		for(PackLog packLog : packLogList) {

			packGraphDtoList.add(PackGraphDto.builder()
					.createdAt(packLog.getCreatedAt())
					.voltage(packLog.getVoltageP())
					.current(packLog.getCurrent())
					.temp(packLog.getTempP())
					.build());
		}

		return packGraphDtoList;
	}

	// SoH 그래프 데이터 조회
	public List<Map<String, Object>> getSoHGraphData(Long carId) {

		String accountId = securityService.getUser().getId();

		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));

		//사용자의 차가 맞는지, 활성화 되어있는지 확인
		if(!car.getUser().getUserId().equals(accountId) || !car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

		List<BmsSoh> bmsSohList = bmsSohRepository.findAllByCarOrderByCycle(car);

		if (bmsSohList.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

		List<Map<String, Object>> dataList = new ArrayList<>();

		for (BmsSoh bmsSoh : bmsSohList) {
			Map<String, Object> map = new HashMap<>();
			map.put("cycle", bmsSoh.getCycle());
			map.put("SOH", bmsSoh.getPrediction());

			dataList.add(map);
		}

		return dataList;
	}

//	친환경 데이터 조회
    public BmsEchoDto getEchoData(String accountId) {

		User user = userRepository.findUserByUserId(accountId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));

		List<Car> cars = carRepository.findByUserAndIsActivate(user, true);

//		차량 0대일 때 예외처리
		if (cars.isEmpty()) {
			throw new CustomException(ErrorCode.NO_MATCH_CAR);
		}

		Float fuelSave = 0f;
		Float carbonSave = 0f;
		Integer treeSave = 0;

		for (Car car : cars) {
			BmsAnalysis bmsAnalysis = bmsAnalysisRepository.findTopByCarOrderByIdDesc(car)
					.orElse(null);

			if (bmsAnalysis != null) {
				fuelSave += bmsAnalysis.getFuelSave();
				carbonSave += bmsAnalysis.getCarbonSave();
				treeSave += bmsAnalysis.getTreeSave();
			}

		}

		BmsEchoDto bmsEchoDto = BmsEchoDto.builder()
				.fuelSave(fuelSave)
				.carbonSave(carbonSave)
				.treeSave(treeSave)
				.build();


		return bmsEchoDto;
	}

	//	배터리 예측 데이터 (ai , 이상치) 조회
	public UserBmsPredictDto getPredictData(Long carId) {

		String accountId = securityService.getUser().getId();

	//		carID로 car 조회
		Car car = carRepository.findById(carId)
				.orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));

		//사용자의 차가 맞는지, 활성화 되어있는지 확인
		if(!car.getUser().getUserId().equals(accountId) || !car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_AUTHORITY);
		}

	//		PackLog의 주행중인 가장 최신 cycle 조회
		Integer lastCycle = packLogRepository.findTopByCarAndStatusOrderByIdDesc(car, 2).get().getCycle();

	//		해당 car, 최신 cycle, 주행중 상태의 packLogList data 조회 (주행중 아니면 SoH 값이 없음)
		List<PackLog> packLogList = packLogRepository.findByCarAndCycleAndStatus(car, lastCycle, 2);


		if (packLogList == null || packLogList.isEmpty()) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}
	//		packLogList 중 가장 마지막 data = 최신 data 가져오기
		PackLog latestPackLog = packLogList.get(packLogList.size()-1);

	//		예상 주행 가능 거리
		Float driveDistance = (car.getCarInfo().getBatteryCapacity() * latestPackLog.getSoh() * latestPackLog.getSoc())
				/ car.getCarInfo().getEfficiency();

	//		SoH 예측 데이터의 가장 마지막 cycle 가져오기
		BmsSoh lastBmsSoh = bmsSohRepository.findFirstByCarOrderByCycleDesc(car);

		if (lastBmsSoh == null) {
			throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
		}

	//	가장 최근 주행 시간
		LocalDateTime startTime = packLogList.get(0).getCreatedAt();
		LocalDateTime endTime = packLogList.get(packLogList.size() - 1).getCreatedAt();

		Long driveTime = Duration.between(startTime, endTime).toMinutes();


	//	최신 cycle, 주행중의 packLogList에서 module outlier 집계

		int[] counts = new int[8];
		String[] codes = new String[8];

		for (PackLog packLog : packLogList) {
	//		모듈 찾기
			List<ModuleLog> moduleLogList = moduleLogRepository.findAllByPackLogOrderByModuleCode(packLog);

			if (moduleLogList.size() == 8) {

				for (int i = 0; i < 8; i++) {

					if(moduleLogList.get(i).getOutlier() == null) {
						// moduleLog.outlier 값 없을 때, 집계 시행
						calculateModuleLogOutlier(moduleLogList.get(i));
					}

					counts[i] += moduleLogList.get(i).getOutlier();
					codes[i] = moduleLogList.get(i).getModuleCode();
				}

			}
		}

		List<Map<String, Object>> outlierGraph = new ArrayList<>();

		for (int i = 0; i < 8; i++) {
			Map<String, Object> map = new HashMap<>();
			map.put("code", codes[i]);
			map.put("count", counts[i]);

			outlierGraph.add(map);
		}


		UserBmsPredictDto userBmsPredictDto = UserBmsPredictDto.builder()
				.driveDistance(driveDistance)
				.soh(latestPackLog.getSoh())
				.leftCycle(lastBmsSoh.getCycle())
				.outlierGraph(outlierGraph)
				.driveTime(driveTime)
				.build();


		return userBmsPredictDto;
	}

}
