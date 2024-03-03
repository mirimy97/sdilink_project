package com.sdilink.battery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.sdilink.battery.jwt.JwtProvider;
import com.sdilink.battery.jwt.filter.JwtAuthenticationFilter;
import com.sdilink.battery.jwt.service.RedisService;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity //활성화. 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final JwtProvider jwtProvider;

	private final RedisService redisService;

	/*
	 *  HTTP 보안 구성을 설정
	 * */
	@Override  // 부모 클래스인 WebSecurityConfigurerAdapter의 메서드를 재정의
	protected void configure(HttpSecurity http) throws Exception {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

		// HTTP 기본 인증 : ID, password 문자열을 Base64 로 인코딩하여 전달하는 구조
		// 대신 JWT를 사용한 인증 방식을 적용할 것.
		http.httpBasic().disable() // HTTP 기본 인증 비활성화
			.csrf().disable() // 쿠키 기반이 아닌 JWT 기반이므로 csrf 사용하지 않음
			.formLogin().disable() // 폼 로그인 비활성화
			// CORS 구성 설정 (Cross-Origin 요청에 대한 제어를 가능하게 함)
			.cors().configurationSource(corsConfigurationSource())
			.and()
			// 세션 관리 방식 = STATELESS (세션 사용X, 상태유지 X) : 토큰에 모든 인증정보가 포함되어있기때문
			// 서버 부담을 줄이고 확장성, 성능 향상
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			// 요청에 대한 인가 규칙 설정
			.authorizeRequests()
				// .antMatchers("/path").permitAll() : 경로에 대한 접근을 모두 허용
				.antMatchers("/insurance/api/download").permitAll()
				.antMatchers("/client/expo").permitAll()
				.antMatchers("/insurance/login").permitAll()
				.antMatchers("/insurance/join").permitAll()
				.antMatchers("/client/login").permitAll()
				.antMatchers("/client/regist").permitAll()
				.antMatchers("/client/carinfos").permitAll()
				.antMatchers("/insurance/api/bms").permitAll()
				.antMatchers("/swagger-resources/**").permitAll()
				.antMatchers("/swagger-ui.html", "/webjars/springfox-swagger-ui/**", "/v2/api-docs/**").permitAll()
				.antMatchers("/client").hasAuthority("USER")
				.antMatchers("/insurance").hasAuthority("INSURANCE")
				// 모든 요청에 대해 인증된 사용자만 허용
				.anyRequest().authenticated()
			.and()
			//jwt 인증 필터를 UsernamePasswordAuthenticationFilter 앞에 추가
			.addFilterBefore(new JwtAuthenticationFilter(jwtProvider, redisService), UsernamePasswordAuthenticationFilter.class);
	}

	//passwordEncoder (비밀번호 암호화)
	@Bean
	public BCryptPasswordEncoder encodePassword() {
		return new BCryptPasswordEncoder();
	}


	// CORS 구성설정
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();

		// 모든 origin(출처), 헤더, HTTP메서드에 대해 요청 허용
		configuration.addAllowedOriginPattern("*");
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");
		configuration.addAllowedHeader("*");
		// Authorization 헤더를 노출하도록 설정 -> 클라이언트가 서버에 토큰 전달 가능하도록
		configuration.addExposedHeader("Authorization");
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
