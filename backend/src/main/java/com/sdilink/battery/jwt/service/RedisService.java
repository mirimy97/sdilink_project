package com.sdilink.battery.jwt.service;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class RedisService {

	private final Long refreshPeriod = 1000L * 60 * 60 * 24 * 30;

	private final RedisTemplate<String, String> redisTemplate;


	public void saveRefreshToken(String accessToken, String refreshToken) {
		redisTemplate.opsForValue().set(
				accessToken,
			refreshToken,
			refreshPeriod,
			TimeUnit.MICROSECONDS
		);
	}

	public String getRefreshToken(String accessToken) {
		 return redisTemplate.opsForValue().get(accessToken);
	}

	//삭제
	public void deleteRefreshToken(String accessToken) {
		redisTemplate.delete(accessToken);
	}
}
