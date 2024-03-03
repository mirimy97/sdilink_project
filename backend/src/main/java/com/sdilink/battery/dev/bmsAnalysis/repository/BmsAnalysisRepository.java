package com.sdilink.battery.dev.bmsAnalysis.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sdilink.battery.domain.BmsAnalysis;
import com.sdilink.battery.domain.Car;

public interface BmsAnalysisRepository extends JpaRepository<BmsAnalysis, Long> {

	Optional<BmsAnalysis> findTopByCarOrderByIdDesc(Car car);
}
