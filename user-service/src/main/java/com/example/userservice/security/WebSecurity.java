package com.example.userservice.security;


import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class WebSecurity {

    private final String[] WHITE_LIST = {"/users/**", "/**"};

    @Bean
    protected SecurityFilterChain config(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                .headers(authorize -> authorize.frameOptions().disable())
                .authorizeHttpRequests(authorize -> authorize
                        .antMatchers(WHITE_LIST).permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll())
                .build();
    }
}
