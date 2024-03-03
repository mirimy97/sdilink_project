package com.sdilink.battery.dev.insurance.carinfo.controller;

import com.sdilink.battery.dev.carinfo.dto.CarInfoDto;
import com.sdilink.battery.dev.insurance.carinfo.service.InsCarInfoService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/insurance/carinfos")
@Api(tags = {"보험사 차종 조회"})
public class InsCarInfoController {

    private final InsCarInfoService insCarInfoService;

    @ApiOperation(value = "고객 차종 상세정보 조회")
    @GetMapping("/cars/{carId}")
    public ResponseEntity<Object> getDetailCarInfo(@PathVariable Long carId) {

        CarInfoDto carInfoDto = insCarInfoService.getDetailCarInfo(carId);

        return ResponseEntity.ok(carInfoDto);

    }

}
