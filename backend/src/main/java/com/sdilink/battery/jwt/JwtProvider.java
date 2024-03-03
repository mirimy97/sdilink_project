package com.sdilink.battery.jwt;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.sdilink.battery.domain.Insurance;
import com.sdilink.battery.jwt.dto.JwtToken;
import com.sdilink.battery.jwt.service.RedisService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtProvider {

	@Value("${jwt.secret.key}")
	private String salt;

	private String secretKey;

	// 만료시간 : 1Hour
	private final Long tokenPeriod = 1000L * 60 * 60;

	private final Long refreshPeriod = 1000L * 60 * 60 * 24 * 30;

	private final RedisService redisService;

	@PostConstruct
	protected void init() {
		//secretkey 생성
		secretKey = Base64.getEncoder().encodeToString(salt.getBytes());
	}

	//토큰 생성
	public JwtToken createToken(String accountId, String role) {
		Claims claims = Jwts.claims().setSubject(accountId);
		claims.put("role", role);

		Date now = new Date();
		JwtToken tokenInfo = null;
		if(role.equals("USER")) {
			tokenInfo = new JwtToken(
					Jwts.builder()
							.setClaims(claims)
							.setIssuedAt(now)
							.setExpiration(new Date(now.getTime()+tokenPeriod))
							.signWith(SignatureAlgorithm.HS256, secretKey)
							.compact(),
					//refresh token
					Jwts.builder()
							.setClaims(claims)
							.setIssuedAt(now)
							.setExpiration(new Date(now.getTime()+refreshPeriod))
							.signWith(SignatureAlgorithm.HS256, secretKey)
							.compact()
			);

			//refresh 토큰 redis 에 저장. refresh 토큰 만료 시간이 지나면 자동 삭제됨
			redisService.saveRefreshToken(tokenInfo.getAccessToken(), tokenInfo.getRefreshToken());
			//redisService.saveRefreshToken(tokenInfo.getAccessToken(),accountId);

		}
		else {
			tokenInfo = new JwtToken(
					Jwts.builder()
							.setClaims(claims)
							.setIssuedAt(now)
							.setExpiration(new Date(now.getTime()+tokenPeriod))
							.signWith(SignatureAlgorithm.HS256, secretKey)
							.compact(),
					null
			);
		}

		return tokenInfo;
	}

	public String createApiToken(String accountId) {
		Claims claims = Jwts.claims().setSubject(accountId);
		claims.put("role", "API");

		Date now = new Date();

		String token = Jwts.builder()
			.setClaims(claims)
			.setIssuedAt(now)
			.setExpiration(new Date(now.getTime()+refreshPeriod))
			.signWith(SignatureAlgorithm.HS256, secretKey)
			.compact();
		return token;
	}

	//토큰 검증
	public boolean verifyToken(String token) {
		try {
			Jws<Claims> claims = Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				.parseClaimsJws(token);
			return claims.getBody()
				.getExpiration()
				.after(new Date());
		} catch (Exception e) {
			return false;
		}
	}

	//access token 재발급
	public String recreateAccessToken(String refreshToken) {

		if(refreshToken != null && verifyToken(refreshToken)) {
			String role = getValue(refreshToken, "role");
			String accountId = getAccountId(refreshToken);

			Claims claims = Jwts.claims().setSubject(accountId);
			claims.put("role", role);



			Date now = new Date();

			String token = Jwts.builder()
					.setClaims(claims)
					.setIssuedAt(now)
					.setExpiration(new Date(now.getTime()+tokenPeriod))
					.signWith(SignatureAlgorithm.HS256, secretKey)
					.compact();


			redisService.saveRefreshToken(token, refreshToken);
			return token;
		}
		return null;
	}

	//token 받아와 authentication 정보 넘겨주기


	//토큰에 담겨있는 유저 account 획득. 변경 필요
	public String getAccountId(String token) {
		return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
	}

	//jwt 객체에 담긴 key-value 반환
	public String getValue(String token, String key) {
		Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
		if(claims.containsKey(key)) {
			return claims.get(key).toString();
		} else {
			return "";
		}
	}


}
