package com.gohul.rebuildSecurity.config;

import com.gohul.rebuildSecurity.entity.Role;
import com.gohul.rebuildSecurity.entity.User;
import com.gohul.rebuildSecurity.entity.UserRoleMapping;
import com.gohul.rebuildSecurity.repo.RoleRepo;
import com.gohul.rebuildSecurity.repo.UserRepo;
import com.gohul.rebuildSecurity.repo.UserRoleRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepo userRepo;
    private final UserRoleRepo userRoleRepo;
    private final RoleRepo roleRepo;

    @Override
    public UserDetails loadUserByUsername(String value) throws UsernameNotFoundException {

        Optional<User> userOptional = userRepo.findByEmail(value)
                .or(() -> userRepo.findByUsername(value));

        if(userOptional.isEmpty())
        {
            throw new UsernameNotFoundException("user details is not found with the given vakue:: "+value);
        }
        User user = userOptional.get();
        log.info("Current User Details:: {}", user);
        List<UserRoleMapping> userRoleMap = userRoleRepo.getAllByUserId(user.getId());
        List<Role> roles = roleRepo.getAllByIdIn(userRoleMap.stream()
                                                .map(UserRoleMapping::getRoleId)
                                                .toList());
        log.info("Current User Privileges:: {}", roles.stream().map(Role::getRole).toList());
        return new org.springframework.security.core.userdetails.User(user.getId().toString(), user.getPassword(), roles.stream()
                                                                    .map(role ->
                                                                    new SimpleGrantedAuthority((role.getRole().split("_").length == 1)? "ROLE_" + role.getRole() : role.getRole()))
                                                                    .toList());

    }
}
