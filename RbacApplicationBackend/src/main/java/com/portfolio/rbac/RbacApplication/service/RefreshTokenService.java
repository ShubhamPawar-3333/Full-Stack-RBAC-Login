package com.portfolio.rbac.RbacApplication.service;

import com.portfolio.rbac.RbacApplication.model.RefreshToken;
import com.portfolio.rbac.RbacApplication.model.User;
import com.portfolio.rbac.RbacApplication.repository.RefreshTokenRepository;
import com.portfolio.rbac.RbacApplication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    @Value("%{app.jwt.refreshExpirationMs:604800000}")
    private Long refreshTokenDurationMs;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();
        logger.info("Created refresh token for user: {}", user.getUsername());
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public boolean verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            logger.warn("Expired refresh token deleted for user: {}", token.getUser().getUsername());
            return false;
        }
        return true;
    }

    public int deleteByUserId(Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    int deleted = refreshTokenRepository.deleteByUser(user);
                    logger.info("Deleted {} refresh token for user: {}", deleted, user.getUsername());
                    return deleted;
                })
                .orElse(0);
    }
}
