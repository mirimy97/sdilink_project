package com.sdilink.battery.dev.insurance.carinfo.service;


import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.carinfo.dto.CarInfoDto;
import com.sdilink.battery.dev.carinfo.repository.CarInfoRepository;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.CarInfo;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class InsCarInfoService {

    private final CarInfoRepository carInfoRepository;
    private final CarRepository carRepository;

    public CarInfoDto getDetailCarInfo(Long carId) {

//        carId로 car 가져오기
        Car car = carRepository.findById(carId)
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_ENTITY));

//        car의 carInfoId로 carInfo 정보를 CarInfoDto로 가져오기

        CarInfo carInfo = car.getCarInfo();

        CarInfoDto carInfoDto = CarInfoDto.builder()
                .id(carInfo.getId())
                .modelName(carInfo.getModelName())
                .maker(carInfo.getMaker())
                .efficiency(carInfo.getEfficiency())
                .peopleCapacity(carInfo.getPeopleCapacity())
                .drivingMethod(carInfo.getDrivingMethod())
                .batteryKind(carInfo.getBatteryKind())
                .batteryCapacity(carInfo.getBatteryCapacity())
                .distance(carInfo.getDistance())
                .build();

        return carInfoDto;

    }
}
