package com.sdilink.battery.dev.client.approval.controller;


import com.sdilink.battery.dev.approval.dto.ApprovalStatusDto;
import com.sdilink.battery.dev.client.approval.service.ApprovalService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/client/approvals")
@RequiredArgsConstructor
@Api(tags = {"유저 보험사 정보 요청 관리"})
public class ApprovalController {

    private final ApprovalService approvalService;


    /* 승인 확인 / 거절 체크
    *
    * */
    @ApiOperation(value = "유저 보험사 요청 거절/승인")
    @PostMapping("")
    public ResponseEntity<Object> checkApproval(@RequestBody ApprovalStatusDto approvalStatusDto) {

        ApprovalStatusDto approvalResult = approvalService.changeStatus(approvalStatusDto);
        return ResponseEntity.ok(approvalResult);

        }
    }

