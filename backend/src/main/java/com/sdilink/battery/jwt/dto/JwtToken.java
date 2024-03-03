package com.sdilink.battery.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class JwtToken {

	private String accessToken;
	private String refreshToken;
	//새로운 access 토큰을 발급하는 용도
}
