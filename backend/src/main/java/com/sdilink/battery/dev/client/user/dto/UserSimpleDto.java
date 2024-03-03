package com.sdilink.battery.dev.client.user.dto;


import com.sdilink.battery.domain.User;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UserSimpleDto {

    private Long id;

    private String name;

    private String birth;



}
