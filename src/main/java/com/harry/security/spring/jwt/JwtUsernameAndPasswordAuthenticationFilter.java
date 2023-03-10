package com.harry.security.spring.jwt;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    
    // Adabanyak extends untuk filter, namun saat ini yang digunakan adalah filter username dan password
    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(
        AuthenticationManager authenticationManager, 
        JwtConfig jwtConfig, 
        SecretKey secretKey) {

        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }
    

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication =  new UsernamePasswordAuthenticationToken(
                authenticationRequest.getUsername(),
                authenticationRequest.getPassword()
            );

            Authentication authenticate = authenticationManager.authenticate(authentication); // Pengecekan / validasi Username dan Password JWT
            return authenticate;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    // Persiapan Send Token ke user
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
                
        // Generate token
        String token  = Jwts.builder()
                        .setSubject(authResult.getName()) // isi dari subject
                        .claim("authorities", authResult.getAuthorities()) // isi dari body, Setup isi body/claim dari Payload JWT saat ini dinamai "authorities"
                        .setIssuedAt(new Date())
                        // .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays()))) // expire token dalam hari
                        .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(1).toInstant())) // expire token dalam menit
                        .signWith(secretKey) // Signatur dari token
                        .compact();
                        
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix()+token); // Set Header
        
    }
}
