package com.sdilink.battery.security;

import com.sdilink.battery.jwt.dto.AuthDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class SecurityService {

    public AuthDto getUser() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return  (AuthDto)principal;
    }
}
