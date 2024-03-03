package com.sdilink.battery.dev.client.car.service;

import com.sdilink.battery.dev.bmsAnalysis.dto.InsBmsAnalysisDto;
import com.sdilink.battery.dev.bmsAnalysis.repository.BmsAnalysisRepository;
import com.sdilink.battery.dev.car.dto.InsCarAndClientDto;
import com.sdilink.battery.dev.car.dto.CarRegistDto;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.carinfo.repository.CarInfoRepository;
import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.userbms.repository.UserBmsRepository;
import com.sdilink.battery.domain.*;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Service
@RequiredArgsConstructor
public class CarService {

    private final CarRepository carRepository;
    private final UserBmsRepository userBmsRepository;
    private final UserRepository userRepository;
    private final CarInfoRepository carInfoRepository;
    private final BmsAnalysisRepository bmsAnalysisRepository;



    public List<Map<String, Object>> findByUserId(String userId) {

        User user = userRepository.findUserByUserId(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));

//        해당 user의 활성화 상태(isActivate=true)인 차량 리스트
        List<Car> carList = carRepository.findByUserAndIsActivate(user, true);

        List<Map<String, Object>> carMapList = new ArrayList<>();

        for (Car car : carList) {
            Map<String, Object> carMap = new HashMap<>();
            carMap.put("id", car.getId());
            carMap.put("userId", car.getUser().getUserId());
            carMap.put("modelName", car.getCarInfo().getModelName());
            carMap.put("maker", car.getCarInfo().getMaker());
            carMap.put("packCode", car.getPackCode());
            carMap.put("carNumber", car.getCarNumber());
            carMap.put("createdAt", car.getCreatedAt());
            carMap.put("isActivate", car.getIsActivate());
            carMapList.add(carMap);
        }

        return carMapList;

    }


    /* 차량 인증 및 등록
    * 성공 = user - user_bms 테이블 간 name, birth, car_number 일치, 데이터 생성 -> 200
    * 실패 = 정보 불일치 -> 404
    * */
    public Long create(String userId, CarRegistDto carRegistDto) {

//        가. carNumber로 이미 Car 있음 & 비활성 상태 -> 활성화
        String carNumber = carRegistDto.getCarNumber();

        Car existedCar = carRepository.findCarByCarNumber(carNumber).orElse(null);

        if (existedCar != null && !existedCar.getIsActivate()) {
            existedCar.setActivate(true);
            carRepository.save(existedCar);

            return existedCar.getId();

        } else if (existedCar != null) {
//            나. carNumber로 이미 Car 있음 & 활성 상태
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 차량입니다.");
        } else {
//            다. carNumber로 Car 없음 -> 인증 후 생성
            //        다-1. packCode로 user_bms 테이블 검색

            UserBms userBms = userBmsRepository.findByCarNumber(carNumber);
//         예외) 검색된 user_bms 없을 시 (차량 번호 불일치)
            if (userBms == null) {
                throw new CustomException(ErrorCode.NO_MATCH_CAR);
            }

//        2. userId 로 user 테이블 검색
            User user = userRepository.findUserByUserId(userId)
                    .orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));

//        user 정보 - user_bms 정보 일치
            if (user.getName().equals(userBms.getName()) && user.getBirth().equals(userBms.getBirth())) {

//            3. 차종 정보 가져오기
                Long carInfoId = carRegistDto.getCarInfoId();
                CarInfo carInfo = carInfoRepository.findById(carInfoId)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CarInfo record not found with id: " + carInfoId));
//            4. Car 생성
                Car newCar = Car.builder()
                        .user(user)
                        .carInfo(carInfo)
                        .carNumber(carNumber)
                        .packCode(userBms.getPackCode())
                        .build();

                Car savedCar = carRepository.save(newCar);
                return savedCar.getId();

            } else {
                throw new CustomException(ErrorCode.NOT_FOUND_ENTITY);
            }

        }

    }


    /* 차량 정보 삭제 (비활성화)
    * 성공 = carId 검색 성공 / is_activate = false -> 200
    * 실패 = 검색 실패 -> 404
    * */
    public Map<String, Long> deactivate(Long carId) {
        Car car = carRepository.findById(carId)
                .orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_CAR));

        car.setActivate(false);
        carRepository.save(car);

        Map<String, Long> deletedCarId = new HashMap<>();
        deletedCarId.put("car_id", carId);

        return deletedCarId;
    }


    public List<Car> findByUser(User user) {
        return carRepository.findByUserAndIsActivate(user, true);
    }

    }


