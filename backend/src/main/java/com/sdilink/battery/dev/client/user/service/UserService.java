package com.sdilink.battery.dev.client.user.service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.sdilink.battery.dev.client.user.dto.UserDto;
import com.sdilink.battery.dev.client.user.dto.UserSimpleDto;
import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.expoToken.dto.ExpoTokenDto;
import com.sdilink.battery.dev.expoToken.repository.ExpoTokenRepository;
import com.sdilink.battery.domain.ExpoToken;
import com.sdilink.battery.domain.User;
import com.sdilink.battery.exception.common.CustomException;
import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.jwt.JwtProvider;
import com.sdilink.battery.jwt.dto.AccessToken;
import com.sdilink.battery.jwt.dto.JwtToken;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final JwtProvider jwtProvider;

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder;

    private final ExpoTokenRepository expoTokenRepository;

    /* 유저 생성
    * 필수 : 아이디, 비밀번호, 생년월일(6자리), 이름 */
    public Long create(UserDto userDto) {
        //user 중복 체크
        Optional<User> findUser = userRepository.findUserByUserId(userDto.getUserId());

        if(findUser.isPresent()) {
            throw new CustomException(ErrorCode.ALREADY_EXIST_USER);
        }

        User newUser = User.builder()
                .userId(userDto.getUserId())
                .userPwd(passwordEncoder.encode(userDto.getUserPwd()))
                .birth(userDto.getBirth())
                .name(userDto.getName())
                .build();
        Long userId = userRepository.save(newUser).getId();

        return userId;
    }

    public Map<String, Object> login(String id, String password) {
        Optional<User> optionalUser = userRepository.findUserByUserId(id);

        if(optionalUser.isEmpty()) {
            throw new CustomException(ErrorCode.NOT_FOUND_USER);
        }

        User user = optionalUser.get();

        if(!passwordEncoder.matches(password, user.getUserPwd())){
            throw new CustomException(ErrorCode.PASSWORD_ERROR);
        }
        Map<String, Object> map = new HashMap<>();

        //인증 정보 기반으로 JWT 토큰 생성
        JwtToken tokenInfo = jwtProvider.createToken(user.getUserId(), "USER");

        map.put("accessToken", tokenInfo.getAccessToken());

        UserSimpleDto userSimpleDto = new UserSimpleDto();
        userSimpleDto.setId(user.getId());
        userSimpleDto.setName(user.getName());
        userSimpleDto.setBirth(user.getBirth());

        map.put("user", userSimpleDto);

        return map;
    }

    public User findUserByUserId(String userId) {
        User user = userRepository.findUserByUserId(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.NO_MATCH_USER));
        return user;
    }

}
