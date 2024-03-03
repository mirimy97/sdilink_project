package com.sdilink.battery.dev.client.user.repository;

import java.util.Optional;

import com.sdilink.battery.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findUserByUserId(String userId);


}
