package com.harry.security.spring.scurity;

import static com.harry.security.spring.scurity.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.harry.security.spring.auth.ApplicationUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
    
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder); // Mengijinkan / Melakukan encode terhadap password
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }
    
}
