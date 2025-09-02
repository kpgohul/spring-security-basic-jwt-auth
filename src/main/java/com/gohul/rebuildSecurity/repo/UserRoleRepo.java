package com.gohul.rebuildSecurity.repo;

import com.gohul.rebuildSecurity.entity.UserRoleMapping;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface UserRoleRepo extends CrudRepository<UserRoleMapping, Long> {

    List<UserRoleMapping> getAllByUserId(Long id);
}
