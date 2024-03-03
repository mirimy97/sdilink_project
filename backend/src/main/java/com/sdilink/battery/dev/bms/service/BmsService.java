package com.sdilink.battery.dev.bms.service;


import com.sdilink.battery.dev.bms.dto.BmsInputDto;
import com.sdilink.battery.dev.bms.repository.CellLogRepository;
import com.sdilink.battery.dev.bms.repository.ModuleLogRepository;
import com.sdilink.battery.dev.bms.repository.PackLogRepository;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.CellLog;
import com.sdilink.battery.domain.ModuleLog;
import com.sdilink.battery.domain.PackLog;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class BmsService {

    private final PackLogRepository packLogRepository;
    private final ModuleLogRepository moduleLogRepository;
    private final CellLogRepository cellLogRepository;

    private final CarRepository carRepository;

    public boolean saveBmsInput(BmsInputDto bmsInputDto) throws Exception{
//        1. pack_code로 Car 검색
        String packCode = bmsInputDto.getPackCode();
        Car car = carRepository.findByPackCode(packCode);

        if (car == null) {
            throw new CustomException(ErrorCode.NO_MATCH_CAR);
        }


//        2. PackLog 저장

//        같은 pack_code + created_at


        PackLog packLog = PackLog.builder()
                .car(car)
                .packCode(packCode)
                .voltageP(bmsInputDto.getVoltageP())
                .current(bmsInputDto.getCurrent())
                .tempP(bmsInputDto.getTempP())
                .status(bmsInputDto.getStatus())
                .capacity(bmsInputDto.getCapacity())
                .soc(bmsInputDto.getSoc())
                .soh(bmsInputDto.getSoh())
                .cycle(bmsInputDto.getCycle())
                .createdAt(bmsInputDto.getCreatedAt())
                .build();

        PackLog savedPackLog = packLogRepository.save(packLog);

//        3. Module Log 저장

        ModuleLog moduleLog = ModuleLog.builder()
                .packLog(savedPackLog)
                .moduleCode(bmsInputDto.getModuleCode())
                .voltageM(bmsInputDto.getVoltageM())
                .tempM(bmsInputDto.getTempM())
                .createdAt(bmsInputDto.getCreatedAt())
                .build();

        ModuleLog savedModuleLog = moduleLogRepository.save(moduleLog);

//        4. Cell Log 저장

        CellLog cellLog = CellLog.builder()
                .moduleLog(savedModuleLog)
                .cellCode(bmsInputDto.getCellCode())
                .voltageC(bmsInputDto.getVoltageC())
                .createdAt(bmsInputDto.getCreatedAt())
                .build();

        cellLogRepository.save(cellLog);


        return true;
    };
}
