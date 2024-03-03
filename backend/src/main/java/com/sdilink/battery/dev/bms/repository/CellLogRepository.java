package com.sdilink.battery.dev.bms.repository;

import java.time.LocalDateTime;
import java.util.List;

import com.sdilink.battery.domain.CellLog;
import com.sdilink.battery.domain.ModuleLog;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CellLogRepository extends JpaRepository<CellLog, Long> {

	List<CellLog> findAllByModuleLog(ModuleLog moduleLog);


	List<CellLog> findAllByCellCodeAndCreatedAtBetween(String cellCode, LocalDateTime startTime, LocalDateTime endTime);
}
