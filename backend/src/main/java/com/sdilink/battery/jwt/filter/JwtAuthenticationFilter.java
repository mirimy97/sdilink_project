package com.sdilink.battery.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.exception.dto.ErrorDto;
import com.sdilink.battery.jwt.JwtProvider;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.jwt.service.RedisService;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
// GenericFilterBean : 상속하는 대상을 필터로 등록될 수 있게 만들어주고, filter 동작 수행할 수 있도록 해줌
	private final JwtProvider jwtProvider;

	private final RedisService redisService;

	//header 의 토큰을 추출함
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		// request header 에서 jwt 토큰 추출
		String token = request.getHeader("Authorization");

		Authentication auth = null; //인증 정보를 저장

		if(token != null) {

			if(!jwtProvider.verifyToken(token)) {
				//access token 재발급
				String refreshToken = redisService.getRefreshToken(token);
				if(refreshToken!=null) redisService.deleteRefreshToken(token);


				token = jwtProvider.recreateAccessToken(refreshToken);

				if(token == null) {
					filterChain.doFilter(request, response);
				}

				response.setHeader("Authorization", token);
			}

			if(token != null) {
				//token 으로 id 읽어오기
				String accountId = jwtProvider.getAccountId(token);
				String role = jwtProvider.getValue(token, "role");


				//role 에 따라 다르게 authentication 주기
				if ("INSURANCE".equals(role)) {
					auth = getAuthentication(accountId, "INSURANCE");
				} else if ("USER".equals(role)) {
					auth = getAuthentication(accountId, "USER");
				}
				else if ("API".equals(role)) {
					auth = getAuthentication(accountId, "API");
				}
				else {
					//예외처리
					setErrorResponse(response, ErrorCode.INTERNAL_SERVER_ERROR);
					return;
				}
				//securityContext 에 auth 저장
				SecurityContextHolder.getContext().setAuthentication(auth);
			}

		}

		filterChain.doFilter(request, response); //다음 filter 로 연결

	}

	private void setErrorResponse(
		HttpServletResponse response,
		ErrorCode errorCode
	){
		ObjectMapper objectMapper = new ObjectMapper();
		response.setStatus(errorCode.getStatus());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		ErrorDto errorResponse = new ErrorDto(errorCode.getStatus(), errorCode.getMessage());
		try{
			response.setCharacterEncoding("UTF-8");
			response.setContentType("text/html; charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
		}catch (IOException e){
			e.printStackTrace();
		}
	}

	private Authentication getAuthentication(String id, String role) {
		AuthDto authDto = new AuthDto().
			builder().id(id).build();

		return new UsernamePasswordAuthenticationToken(authDto, "", List.of(new SimpleGrantedAuthority(role)));
	}


}
