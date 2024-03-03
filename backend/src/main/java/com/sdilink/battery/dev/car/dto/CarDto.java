package com.sdilink.battery.dev.car.dto;

import com.sdilink.battery.domain.CarInfo;
import com.sdilink.battery.domain.User;
import lombok.*;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class CarDto {

    private Long id;
    private User user;
    private CarInfo carInfo;
    private String packCode;
    private String carNumber;
    private LocalDateTime createdAt;
    private Boolean isActivate;

}
