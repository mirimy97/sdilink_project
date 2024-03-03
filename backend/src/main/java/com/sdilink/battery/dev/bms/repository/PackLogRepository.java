package com.sdilink.battery.dev.bms.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.PackLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PackLogRepository extends JpaRepository<PackLog, Long> {

	Optional<PackLog> findTopByCarOrderByIdDesc(Car car);

	List<PackLog> findAllByCarAndCreatedAtBetween(Car car, LocalDateTime startTime, LocalDateTime endTime);

	List<PackLog> findByCarAndCycleAndStatus(Car car, Integer lastCycle, int i);

	PackLog findFirstByCycleAndStatusOrderByIdDesc(int cycle, int status);

	Optional<PackLog> findTopByCarAndStatusOrderByIdDesc(Car car, int status);

	Optional<PackLog> findByCarAndCreatedAtAndStatus(Car car, LocalDateTime dateTime, int status);

	List<PackLog> findAllByCarAndStatusAndCreatedAtBetween(Car car, int status, LocalDateTime startTime, LocalDateTime endTime);

	List<PackLog> findTop180ByCarOrderByIdDesc(Car car);
}
