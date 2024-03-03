package com.sdilink.battery.jwt.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sdilink.battery.exception.constants.ErrorCode;
import com.sdilink.battery.exception.dto.ErrorDto;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class JwtController {

	@GetMapping("/expired")
	public ResponseEntity<Object> notSecured(){

		return new ResponseEntity(new ErrorDto(ErrorCode.NO_AUTHORITY.getStatus(), ErrorCode.NO_AUTHORITY.getMessage()), HttpStatus.valueOf(ErrorCode.NO_AUTHORITY.getStatus()));

	}
}
