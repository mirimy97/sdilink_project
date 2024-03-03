package com.sdilink.battery.dev.expoToken.repository;

import com.sdilink.battery.domain.ExpoToken;
import com.sdilink.battery.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExpoTokenRepository extends JpaRepository<ExpoToken, Long> {

    ExpoToken findByUser(User user);
}
