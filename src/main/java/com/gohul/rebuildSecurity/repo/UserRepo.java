package com.gohul.rebuildSecurity.repo;

import com.gohul.rebuildSecurity.entity.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends CrudRepository<User, Long> {

    Optional<User> findByUsername(String name);

    Optional<User> findByEmail(String name);
    

}
