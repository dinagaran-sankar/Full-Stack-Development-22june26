package com.learning.jwttoken.SecurityConfig;

import com.learning.jwttoken.Generator.JwtTokenGenerator;
import com.learning.jwttoken.Validator.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

@Configuration
@RequiredArgsConstructor
public class BasicSecurityConfig {

    private final JwtTokenGenerator jwtTokenGenerator;
    //private final JwtTokenValidator jwtTokenValidator;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf-> csrf.disable())
                .addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
                .addFilterAfter(jwtTokenGenerator,BasicAuthenticationFilter.class)
                .authorizeHttpRequests((request)->{
                    request .requestMatchers("/api/jwts/loginUser","/api/jwts/refreshToken")
                            .permitAll()
                            .anyRequest()
                            //.hasRole("ADMIN")
                            .authenticated();
                })
                //.formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
        .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        System.out.println("inside user details service");
        User.UserBuilder roles = User.withUsername("dina")
                .password(passwordEncoder().encode("dina1234")).roles("ADMIN");
        User.UserBuilder userBuilder =  User.withUsername("Amma")
                        .password(passwordEncoder().encode("amma1234")).roles("USER");
                return new InMemoryUserDetailsManager(roles.build(),userBuilder.build());

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }
}
