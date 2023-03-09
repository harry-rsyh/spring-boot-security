package com.harry.security.spring.scurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.harry.security.spring.scurity.ApplicationUserRole.*;
import static com.harry.security.spring.scurity.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    private final PasswordEncoder passwordEncoder;
    
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // TODO: Next Learn
            .authorizeRequests()
            .antMatchers("/","index","/css/*","/js/*").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name()) // Apakah Role nya STUDENT
            .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // Apakah memiliki otoritas COURSE WRITE
            .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // Apakah memiliki otoritas COURSE WRITE
            .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission()) // Apakah memiliki otoritas COURSE WRITE
            .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) // Jika DIPINDAH URUTANYA keatas Maka antMatcher Method POST, PUT, DELETE akan diabaikan dan Juga karena ini method terakhir yang di check Maka kita tidak perlu memberikan "HttpMethod.GET"
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
    }
    
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
            .username("annasmith")
            .password(passwordEncoder.encode("password"))
            // .roles(STUDENT.name())
            .authorities(STUDENT.getGrantedAuthorities())
            .build();

        UserDetails lindaUser = User.builder()
            .username("linda")
            .password(passwordEncoder.encode("password"))
            // .roles(ADMIN.name())
            .authorities(ADMIN.getGrantedAuthorities())
            .build();

        UserDetails tomUser = User.builder()
            .username("tom")
            .password(passwordEncoder.encode("password"))
            // .roles(ADMINTRAINEE.name())
            .authorities(ADMINTRAINEE.getGrantedAuthorities())
            .build();
        
        return new InMemoryUserDetailsManager(
            annaSmithUser,
            lindaUser,
            tomUser
        );
    }
}
