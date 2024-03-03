package com.sdilink.battery.dev.client.carInfo.service;

import com.sdilink.battery.dev.carinfo.repository.CarInfoRepository;
import com.sdilink.battery.domain.CarInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CarInfoService {

    private final CarInfoRepository carInfoRepository;

    public List<CarInfo> findAll() {
        return carInfoRepository.findAll();
    }
}
