package com.sdilink.battery.dev.insurance.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class InsuranceDto {

	private Long id;

	private String accountId;

	private String accountPwd;

	private String name;

}
