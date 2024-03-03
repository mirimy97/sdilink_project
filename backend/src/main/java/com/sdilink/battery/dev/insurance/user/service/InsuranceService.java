package com.sdilink.battery.dev.insurance.user.service;

import java.util.*;

import com.sdilink.battery.dev.insurance.user.dto.InsuranceInfoDto;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sdilink.battery.dev.car.dto.CarSerachDto;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.insurance.user.dto.InsuranceDto;
import com.sdilink.battery.dev.insurance.user.repository.InsuranceRepository;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.Insurance;
import com.sdilink.battery.jwt.JwtProvider;
import com.sdilink.battery.jwt.dto.JwtToken;

import lombok.AllArgsConstructor;

@Service
@Transactional
@AllArgsConstructor
public class InsuranceService {

	private final JwtProvider jwtProvider;

	private final BCryptPasswordEncoder passwordEncoder;

	private final InsuranceRepository insuranceRepository;

	private final CarRepository carRepository;



	public Map<String, Object> login(String id, String password){
			//Insurance 조회
			Optional<Insurance> optionalInsurance = insuranceRepository.findInsuranceByAccountId(id);

			if(optionalInsurance.isEmpty()){
				//custom 해야함
				throw new CustomException(ErrorCode.NOT_FOUND_USER);
			}
			Insurance insurance = optionalInsurance.get();

			if(!passwordEncoder.matches(password, insurance.getAccountPwd())){
				throw new CustomException(ErrorCode.PASSWORD_ERROR);
			}

			insurance.setLoginDate();

			Map<String, Object> map = new HashMap<>();

			InsuranceInfoDto insuranceInfoDto = InsuranceInfoDto.builder()
					.name(insurance.getName())
					.imgSrc(insurance.getImageSrc())
					.loginDate(insurance.getLoginDate())
					.build();

			// 3. 인증 정보를 기반으로 JWT 토큰 생성
			JwtToken tokenInfo = jwtProvider.createToken(id, "INSURANCE");

			map.put("accessToken", tokenInfo.getAccessToken());
			map.put("insurance", insuranceInfoDto);

			//refresh token 저장

			return map;
	}

	public void addInsurance(String username, String password, String name) {

		insuranceRepository.save(Insurance.builder()
				.accountId(username)
				.accountPwd(passwordEncoder.encode(password))
				.name(name)
			.build());

	}

	public InsuranceDto getInsurance(String id) {
		Insurance insurance = insuranceRepository.findInsuranceByAccountId(id).get();
		return InsuranceDto.builder()
			.id(insurance.getId())
			.accountId(insurance.getAccountId())
			.accountPwd(insurance.getAccountPwd())
				.name(insurance.getName())
			.build();
	}

	public CarSerachDto getUserInfo(CarSerachDto carSearchDto)  {

		Optional<Car> optionalCar = carRepository.findCarByCarNumber(carSearchDto.getCarNumber());

		if(optionalCar.isEmpty()) {
			throw new CustomException(ErrorCode.NO_MATCH_CAR);
		}
		Car car = optionalCar.get();

		if(!car.getUser().getName().equals(carSearchDto.getUserName()) || !car.getIsActivate()) {
			throw new CustomException(ErrorCode.NO_MATCH_USER);
		}

		carSearchDto.setCarId(car.getId());

		return carSearchDto;
	}


}
