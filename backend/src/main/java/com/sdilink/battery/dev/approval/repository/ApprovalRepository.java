package com.sdilink.battery.dev.approval.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.sdilink.battery.domain.Car;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.sdilink.battery.domain.Approval;
import com.sdilink.battery.domain.Insurance;

public interface ApprovalRepository extends JpaRepository<Approval, Long> {

	@Query("select a from Approval a where a.insurance.id = :insuranceId and (a.authTime is null or a.authTime >= :time)")
	List<Approval> findAllByInsurance(Long insuranceId, LocalDateTime time);

    @Query("SELECT a FROM Approval a WHERE a.insurance = :insurance AND a.car = :car AND a.createdAt = (SELECT MAX(a2.createdAt) FROM Approval a2 WHERE a2.insurance = :insurance AND a2.car = :car)")
    Optional<Approval> findLatestApprovalByInsuranceAndCar(@Param("insurance") Insurance insurance, @Param("car") Car car);

	@Query("SELECT a FROM Approval a WHERE a.car = :car AND a.isApprove = 1 AND DATEDIFF(a.authTime, :time) <= 15")
	List<Approval> findLatestApprovalByCar(Car car, LocalDateTime time);

    List<Approval> findByCarId(Long carId);

    List<Approval> findByCarIn(List<Car> carList);

    Approval findFirstByInsuranceAndCarAndIsApproveOrderByAuthTimeDesc(Insurance insurance, Car car, int isApprove);

	Optional<Approval> findTopByInsuranceAndCarAndIsApproveOrderByIdDesc(Insurance insurance, Car car, int isApprove);
}
