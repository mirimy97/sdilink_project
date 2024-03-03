package com.sdilink.battery.dev.insurance.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sdilink.battery.domain.Insurance;

public interface InsuranceRepository extends JpaRepository<Insurance, Long> {

	Optional<Insurance> findInsuranceByAccountId(String accountId);

}
