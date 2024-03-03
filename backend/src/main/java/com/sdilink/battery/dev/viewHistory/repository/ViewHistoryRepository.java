package com.sdilink.battery.dev.viewHistory.repository;

import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.Insurance;
import com.sdilink.battery.domain.ViewHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ViewHistoryRepository extends JpaRepository<ViewHistory, Long> {


    List<ViewHistory> findByCarIn(List<Car> carList);

    List<ViewHistory> findFirst10ByInsuranceOrderByCreatedAtDesc(Insurance insurance);
}
