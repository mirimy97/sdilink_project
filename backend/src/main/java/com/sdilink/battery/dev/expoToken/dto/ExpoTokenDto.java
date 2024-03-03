package com.sdilink.battery.dev.expoToken.dto;


import com.sdilink.battery.domain.User;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.*;
import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class ExpoTokenDto {

    //    id
    private Long id;

    // FK  - User
    private Long userId;

    // token
    private String token;

}
