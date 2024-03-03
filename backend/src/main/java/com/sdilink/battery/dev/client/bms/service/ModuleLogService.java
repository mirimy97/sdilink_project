package com.sdilink.battery.dev.client.bms.service;


import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.dev.bms.repository.CellLogRepository;
import com.sdilink.battery.dev.bms.repository.ModuleLogRepository;
import com.sdilink.battery.domain.CellLog;
import com.sdilink.battery.domain.ModuleLog;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.security.SecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ModuleLogService {

    private final ModuleLogRepository moduleLogRepository;
    private final CellLogRepository cellLogRepository;
    private final SecurityService securityService;

    public List<CellLogDto> getCellDataByModuleId(Long moduleLogId) {

//        모듈로그id 로 검색 -> 모듈 일련번호 + 시간대 일치하는 ModuleLog
        ModuleLog moduleLog = moduleLogRepository.findById(moduleLogId)
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_ENTITY));

//        본인 인증
        String accountId = securityService.getUser().getId();

        if (!moduleLog.getPackLog().getCar().getUser().getUserId().equals(accountId)) {
            throw new CustomException(ErrorCode.NO_AUTHORITY);
        }

//        moduleLog를 참조하는 cellLog List
        List<CellLog> cellLogs = cellLogRepository.findAllByModuleLog(moduleLog);

//        CellLogDto 로 일괄 변환
        List<CellLogDto> cellLogDtoList = new ArrayList<>();

        for (CellLog cellLog : cellLogs) {
            cellLogDtoList.add(CellLogDto.builder()
                    .id(cellLog.getId())
                    .cellCode(cellLog.getCellCode())
                    .voltageC(cellLog.getVoltageC())
                    .outlier(cellLog.getOutlier())
                    .isNormal(cellLog.getIsNormal() != null ? cellLog.getIsNormal() : -1)
                    .build());
        }

        return cellLogDtoList;
    }
}
