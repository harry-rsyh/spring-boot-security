package com.harry.security.spring.scurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.harry.security.spring.scurity.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import static com.harry.security.spring.scurity.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    private final PasswordEncoder passwordEncoder;
    
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/","index","/css/*","/js/*").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name()) // Apakah Role nya STUDENT
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
                .loginPage("/login").permitAll() // akan diarahkan sesuai Template Controller (menggunakan thymeleaf), jgn lupa di permitAll untuk semua user
                .defaultSuccessUrl("/courses", true) // ketika login success maka halaman pertama yang akan diaksess
                .passwordParameter("password") // Mengganti name di html form login name="..."
                .usernameParameter("username") // Mengganti name di html form login name="..."
            .and()
            .rememberMe() // default 2 minggu
                .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // Waktu valid token bisa digunakan
                .key("somethingsecure") // key token
                .rememberMeParameter("remember-me") // Mengganti name di html form login name="..."
            .and()
            .logout() // Customize Logout
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // Karena kita disable CSRF maka kita bisa pakai GET untuk logout
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me") // Jangan Lupa delete cookies yang tidak digunakan
                .logoutSuccessUrl("/login"); // ketika logout success jangan lupa arahkan kembali ke login url
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
