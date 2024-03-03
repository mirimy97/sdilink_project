package com.sdilink.battery.dev.car.repository;

import java.util.List;
import java.util.Optional;

import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CarRepository extends JpaRepository<Car, Long> {

	Optional<Car> findCarByCarNumber(String carNumber);

    List<Car> findByUserAndIsActivate(User user, boolean isActivate);

    Car findByPackCode(String packCode);


}
