package com.sdilink.battery.dev.userbms.repository;

import com.sdilink.battery.domain.UserBms;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserBmsRepository extends JpaRepository<UserBms, Long> {
//    UserBms findBypackCode(String packCode);
    UserBms findByCarNumber(String carNumber);
}
