package com.harry.security.spring.jwt;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    // Adabanyak extends untuk filter, namun saat ini yang digunakan adalah filter username dan password

    private final AuthenticationManager authenticationManager;

    @Autowired
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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
                
        String key = "Loremipsumdolorsitametconsecteturadipisi";

        // Generate token
        String token  = Jwts.builder()
                        .setSubject(authResult.getName()) // isi dari subject
                        .claim("authorities", authResult.getAuthorities()) // isi dari body, Setup isi dari Payload JWT 
                        .setIssuedAt(new Date())
                        .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) // expire token
                        .signWith(Keys.hmacShaKeyFor(key.getBytes())) // Signatur dari token
                        .compact();
                        
        response.addHeader("Authorization", "Bearer "+token); // Set Header
        
    }
}
