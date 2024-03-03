package com.sdilink.battery.dev.carinfo.repository;

import com.sdilink.battery.domain.CarInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CarInfoRepository extends JpaRepository<CarInfo, Long> {

}
