package com.portfolio.rbac.RbacApplication.repository;

import com.portfolio.rbac.RbacApplication.model.RefreshToken;
import com.portfolio.rbac.RbacApplication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    int deleteByUser(User user);
}
