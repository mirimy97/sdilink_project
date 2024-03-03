package com.sdilink.battery.dev.insurance.security;

import com.sdilink.battery.dev.insurance.user.repository.InsuranceRepository;
import com.sdilink.battery.domain.Insurance;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final InsuranceRepository insuranceRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Insurance insurance = insuranceRepository.findInsuranceByAccountId(username).orElseThrow(
                () -> new RuntimeException("Invalid Authentication!")
        );

        return new InsuranceDetails(insurance);
    }
}
