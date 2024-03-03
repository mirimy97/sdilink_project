package com.sdilink.battery.dev.client.totalHistory.controller;



import com.sdilink.battery.dev.client.approval.service.ApprovalService;
import com.sdilink.battery.dev.client.car.service.CarService;
import com.sdilink.battery.dev.viewHistory.dto.TotalHistoryDto;
import com.sdilink.battery.dev.client.user.service.UserService;
import com.sdilink.battery.dev.client.viewHistory.service.ViewHistoryService;
import com.sdilink.battery.domain.Approval;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.User;
import com.sdilink.battery.domain.ViewHistory;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.security.SecurityService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/client/histories")
@RequiredArgsConstructor
@Slf4j
@Api(tags = {"유저 히스토리 조회"})
public class TotalHistoryController {

    private final ViewHistoryService viewHistoryService;
    private final ApprovalService approvalService;
    private final UserService userService;
    private final CarService carService;
    private final SecurityService securityService;

    @ApiOperation(value = "user의 모든 car에 대해 승인 및 조회 내역 검색")
    @GetMapping("")
    public ResponseEntity<Object> findTotalHistorybyCarId() {
//        토큰으로 사용자 정보 가져오기
        AuthDto authDto = securityService.getUser();

//        사용자 계정 정보로 carList 가져오기
        User user = userService.findUserByUserId(authDto.getId());

        List<Car> carList = carService.findByUser(user);

//        조회내역 (ViewHistory), 승인내역 (Approval) 에서 각각 CarId로 검색한 결과 List 가져옴
        List<ViewHistory> viewHistoryList = viewHistoryService.findByCarIn(carList);
        List<Approval> approvalList = approvalService.findByCarIn(carList);

//        TotalHistoryDto ArrayList 생성하여 위 List들 추가
        List<TotalHistoryDto> historyDtoList = new ArrayList<>();

        historyDtoList.addAll(viewHistoryList.stream().map(TotalHistoryDto::new).collect(Collectors.toList()));
        historyDtoList.addAll(approvalList.stream().map(TotalHistoryDto::new).collect(Collectors.toList()));

//        시간 역순 정렬
        Collections.sort(historyDtoList, Comparator.comparing(TotalHistoryDto::getCreatedAt).reversed());

//        id값 1, 2, 3, ... 순차적 증가하게 초기화
        for (int i = 0; i < historyDtoList.size(); i++) {
            historyDtoList.get(i).setId(Long.valueOf(i + 1));
        }

        return ResponseEntity.ok(historyDtoList);

    }
}
