package com.sdilink.battery.dev.bmsSoh.repository;

import com.sdilink.battery.domain.BmsSoh;
import com.sdilink.battery.domain.Car;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BmsSohRepository extends JpaRepository<BmsSoh, Long> {
    BmsSoh findFirstByCarOrderByCycleDesc(Car car);

    List<BmsSoh> findAllByCarOrderByCycle(Car car);
}
