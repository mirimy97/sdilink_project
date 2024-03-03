package com.sdilink.battery.dev.insurance.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.sdilink.battery.dev.car.dto.CarSerachDto;
import com.sdilink.battery.dev.car.repository.CarRepository;
import com.sdilink.battery.dev.carinfo.repository.CarInfoRepository;
import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.insurance.user.service.InsuranceService;
import com.sdilink.battery.domain.Car;
import com.sdilink.battery.domain.CarInfo;
import com.sdilink.battery.domain.User;

@SpringBootTest
class InsuranceServiceTest {
	@Autowired private InsuranceService insuranceService;

	@BeforeAll
	public static void beforeAll(@Autowired CarInfoRepository carInfoRepository,@Autowired UserRepository userRepository, @Autowired
		CarRepository carRepository) {
		CarInfo carInfo = CarInfo.builder().modelName("s1").maker("르노자동차").build();
		CarInfo saveCarInfo = carInfoRepository.save(carInfo);

		User user = User.builder()
			.userId("huijin")
			.userPwd("1234")
			.birth("980904")
			.name("양희진")
			.build();

		User saveUser = userRepository.save(user);

		Car car = Car.builder()
			.user(saveUser)
			.carInfo(saveCarInfo)
			.carNumber("123123")
			.packCode("fkjsfhl")
			.build();

		carRepository.save(car);
	}

	@Transactional
	@Test
	public void getUserInfoTest() throws Exception {
		CarSerachDto carSerachDto = new CarSerachDto();
		carSerachDto.setUserName("양희진");
		carSerachDto.setCarNumber("123123");

		CarSerachDto carSerachDto1 = insuranceService.getUserInfo(carSerachDto);

		Assertions.assertThat(carSerachDto1).isEqualTo(carSerachDto);
	}
}