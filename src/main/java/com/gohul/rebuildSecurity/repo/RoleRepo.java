package com.gohul.rebuildSecurity.repo;

import com.gohul.rebuildSecurity.entity.Role;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepo extends CrudRepository<Role, Long> {

    Optional<Role> findByRole(String role);

    List<Role> getAllByIdIn(List<Long> ids);
}
