package com.sdilink.battery.dev.client.user.controller;


import com.sdilink.battery.dev.client.user.dto.UserDto;
import com.sdilink.battery.dev.client.user.dto.UserSimpleDto;
import com.sdilink.battery.dev.client.user.repository.UserRepository;
import com.sdilink.battery.dev.client.user.service.UserService;
import com.sdilink.battery.dev.expoToken.dto.ExpoTokenDto;
import com.sdilink.battery.dev.expoToken.dto.ExpoTokenRequestDto;
import com.sdilink.battery.dev.expoToken.service.ExpoTokenService;
import com.sdilink.battery.domain.ExpoToken;
import com.sdilink.battery.domain.User;
import com.sdilink.battery.jwt.dto.AccessToken;
import com.sdilink.battery.jwt.dto.AuthDto;
import com.sdilink.battery.jwt.dto.JwtToken;

import com.sdilink.battery.security.SecurityService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

@RestController
@RequestMapping("/client")
@RequiredArgsConstructor
@Api(tags = {"유저"})
public class UserController {

    private final UserService userService;
    private final ExpoTokenService expoTokenService;

    private final SecurityService securityService;


    /* User 생성 테스트 */
    // @PostMapping("/regist/temp")
    // public ResponseEntity<?> createUserTest(@RequestBody UserDto userDto) {
    //
    //     User saved = userService.create(userDto);
    //
    //     return ResponseEntity.ok(saved);
    // }

    @ApiOperation(value = "유저 회원가입")
    @PostMapping("/regist")
    public ResponseEntity<?> createUser(@RequestBody @Valid UserDto userDto) {
        Map<String, Object> result = new HashMap<>();

        Long userId = userService.create(userDto);
        result.put("message", "join Success");
        result.put("id", userId);

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @ApiOperation(value = "유저 로그인")
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginForm) {
        Map<String, Object> map = userService.login(loginForm.get("id"), loginForm.get("password"));
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", (String) map.get("accessToken"));

        return ResponseEntity.ok()
            .headers(headers)
            .body(map.get("user"));
    }

    @ApiOperation(value = "expo token 저장")
    @PostMapping("/expo-token")
    public ResponseEntity<?> saveExpoToken(@RequestBody ExpoTokenRequestDto expoTokenRequestDto) {

        String accountId = securityService.getUser().getId();

        ExpoToken savedToken = expoTokenService.saveExpoToken(accountId, expoTokenRequestDto.getExpoToken());

        return ResponseEntity.ok(savedToken);

    }

}
