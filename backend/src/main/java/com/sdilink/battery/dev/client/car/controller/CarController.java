package com.sdilink.battery.dev.client.car.controller;

import com.sdilink.battery.dev.car.dto.CarRegistDto;
import com.sdilink.battery.dev.client.car.service.CarService;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.security.SecurityService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/client/cars")
@RequiredArgsConstructor
@Slf4j
@Api(tags = {"유저 자동차 관리"})
public class CarController {

    private final CarService carService;

    private final SecurityService securityService;

    /* userId로 등록된 Car 가져오기 */
    @ApiOperation(value = "userId로 등록된 Car 가져오기")
    @GetMapping("")
    public ResponseEntity<Object> findCarbyUser() {

        //login 한 유저 정보 가져오는 방법
        AuthDto authDto = securityService.getUser();

        List<Map<String, Object>> response = carService.findByUserId(authDto.getId());

        return ResponseEntity.ok(response);

    }

    /* Car 정보 등록 */
    @PostMapping("")
    @ApiOperation(value = "Car 정보 등록")
    public ResponseEntity<Object> registCar(@RequestBody CarRegistDto carRegistDto) {

        AuthDto authDto = securityService.getUser();

        Long savedCarId = carService.create(authDto.getId(), carRegistDto);
        Map<String, Long> response = new HashMap<>();
        response.put("carId", savedCarId);
        return ResponseEntity.ok(response);
    }

    /* Car 정보 비활성화 */
    @ApiOperation(value = "Car 정보 비활성화")
    @DeleteMapping("/{carId}")
    public ResponseEntity<Object> deleteCar(@PathVariable Long carId) {
        Map<String, Long> deletedCarId = carService.deactivate(carId);

        return ResponseEntity.ok(deletedCarId);

    }
}
