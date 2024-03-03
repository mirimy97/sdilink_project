package com.sdilink.battery.dev.bms.controller;

import com.sdilink.battery.dev.bms.dto.BmsInputDto;
import com.sdilink.battery.dev.bms.service.BmsService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/bms")
@RequiredArgsConstructor
@Api(tags = {"BMS 데이터"})
public class BmsController {

    private final BmsService bmsService;

    @ApiOperation(value = "bms 데이터 저장 (임시)")
    @PostMapping("")
    public ResponseEntity<?> saveBmsData(@RequestBody BmsInputDto bmsInputDto) {

        try {
            bmsService.saveBmsInput(bmsInputDto);
            return ResponseEntity.ok().build();
        }
        catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
