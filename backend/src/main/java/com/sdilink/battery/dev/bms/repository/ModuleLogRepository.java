package com.sdilink.battery.dev.bms.repository;

import java.time.LocalDateTime;
import java.util.List;

import com.sdilink.battery.dev.bms.dto.CellLogDto;
import com.sdilink.battery.domain.ModuleLog;
import com.sdilink.battery.domain.PackLog;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ModuleLogRepository extends JpaRepository<ModuleLog, Long> {

	List<ModuleLog> findAllByPackLog(PackLog packLog);

	List<ModuleLog> findAllByModuleCodeAndCreatedAtBetween(String moduleCode, LocalDateTime startTime, LocalDateTime endTime);

	List<ModuleLog> findByCreatedAtBetween(LocalDateTime startTime, LocalDateTime endTime);

    List<ModuleLog> findAllByPackLogOrderByModuleCode(PackLog packLog);
}
