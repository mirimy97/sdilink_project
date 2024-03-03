package com.sdilink.battery.dev.client.user.dto;


import lombok.*;

import java.time.LocalDateTime;

import javax.validation.constraints.NotBlank;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class UserDto {

    private Long id;

    @NotBlank
    private String userId;

    @NotBlank
    private String userPwd;

    @NotBlank
    private String birth;

    @NotBlank
    private String name;
    private LocalDateTime createdAt;
    private LocalDateTime lastActDate;
    private Boolean isActivate;
    private Boolean isWithdraw;
    private Boolean isAuth;

}
