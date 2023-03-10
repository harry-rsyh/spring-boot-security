package com.harry.security.spring.auth;

import static com.harry.security.spring.scurity.ApplicationUserRole.ADMIN;
import static com.harry.security.spring.scurity.ApplicationUserRole.ADMINTRAINEE;
import static com.harry.security.spring.scurity.ApplicationUserRole.STUDENT;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake") // nama bean dari fake database yang akan di gunakan
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;
    
    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }
    
    private List<ApplicationUser> getApplicationUsers(){

        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                "annasmith", 
                passwordEncoder.encode("password"),
                STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true
                ),
            new ApplicationUser(
                "linda", 
                passwordEncoder.encode("password"),
                ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true
                ),
            new ApplicationUser(
                "tom", 
                passwordEncoder.encode("password"),
                ADMINTRAINEE.getGrantedAuthorities(),
                true,
                true,
                true,
                true
                )
        );

        return applicationUsers;
    }
}
