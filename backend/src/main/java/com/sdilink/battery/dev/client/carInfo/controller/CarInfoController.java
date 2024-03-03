package com.sdilink.battery.dev.client.carInfo.controller;

import com.sdilink.battery.dev.client.carInfo.service.CarInfoService;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client/carinfos")
@RequiredArgsConstructor
@Api(tags = {"차종"})
public class CarInfoController {

    private final CarInfoService carInfoService;


    /* 차종 리스트 불러오기 */
    @ApiOperation(value = "차종 리스트 불러오기")
    @GetMapping("")
    public ResponseEntity<Object> zall() {
        return ResponseEntity.ok(carInfoService.findAll());
    }
}
