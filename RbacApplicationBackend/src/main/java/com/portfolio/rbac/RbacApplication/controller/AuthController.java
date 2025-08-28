package com.portfolio.rbac.RbacApplication.controller;

import com.portfolio.rbac.RbacApplication.dto.AuthRequest;
import com.portfolio.rbac.RbacApplication.dto.AuthResponse;
import com.portfolio.rbac.RbacApplication.dto.RegisterRequest;
import com.portfolio.rbac.RbacApplication.model.RefreshToken;
import com.portfolio.rbac.RbacApplication.model.Role;
import com.portfolio.rbac.RbacApplication.model.User;
import com.portfolio.rbac.RbacApplication.repository.UserRepository;
import com.portfolio.rbac.RbacApplication.service.JwtService;
import com.portfolio.rbac.RbacApplication.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000"}, allowCredentials = "true")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @PutMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            logger.warn("Registration failed: Username already exists - {}", request.username());
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));
        }
        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(request.role() == null ? Role.USER : request.role())
                .enabled(true)
                .build();
        User saved = userRepository.save(user);
        logger.info("User registered: {}", saved.getUsername());
        return ResponseEntity.ok(Map.of(
                "message", "Registered",
                "username", saved.getUsername(),
                "role", saved.getRole()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails principal = (UserDetails) authentication.getPrincipal();

        String userRole = principal.getAuthorities().stream().findFirst().orElseThrow().getAuthority();
        String accessToken = jwtService.generateToken(principal, Map.of("role", userRole));

        User user = userRepository.findByUsername(principal.getUsername()).orElseThrow();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        logger.info("Login successful for user: {}", user.getUsername());
        return ResponseEntity.ok(new AuthResponse(accessToken, user.getRole()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            logger.debug("Refresh Failed: No cookies");
            return ResponseEntity.badRequest().body(Map.of("error", "No refresh token"));
        }

        String refreshTokenValue = null;
        for (Cookie c: cookies) {
            if ("refreshToken".equals(c.getName())) {
                refreshTokenValue = c.getValue();
                break;
            }
        }

        if (refreshTokenValue == null) {
            logger.debug("Refresh failed: Refresh Token not found");
            return ResponseEntity.badRequest().body(Map.of("error", "Refresh token not found"));
        }

        return refreshTokenService.findByToken(refreshTokenValue)
                .map(rt -> {
                    if (!refreshTokenService.verifyExpiration(rt)) {
                        logger.warn("Refresh failed: Token expired for user {}", rt.getUser().getUsername());
                        return ResponseEntity.status(403).body(Map.of("error", "Refresh token expired"));
                    }
                    User user = rt.getUser();
                    UserDetails userDetails = org.springframework.security.core.userdetails.User
                            .withUsername(user.getUsername())
                            .password(user.getPassword())
                            .authorities("ROLE_"+user.getRole().name())
                            .accountExpired(false)
                            .accountLocked(false)
                            .credentialsExpired(false)
                            .disabled(!user.isEnabled())
                            .build();

                    String userRole = "ROLE_"+user.getRole().name();
                    String accessToken = jwtService.generateToken(userDetails, Map.of("role", userRole));

                    logger.info("Token refreshed for user: {}", user.getUsername());
                    return ResponseEntity.ok(Map.of("token", accessToken, "role", user.getRole()));
                })
                .orElseGet(() -> {
                    logger.warn("Refresh failed: Invalid refresh token");
                    return ResponseEntity.status(403).body(Map.of("error", "Invalid refresh token"));
                });
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c: cookies) {
                if ("refreshToken".equals(c.getName())) {
                    String token = c.getValue();
                    refreshTokenService.findByToken(token).ifPresent(rt ->
                            refreshTokenService.deleteByUserId(rt.getUser().getId()));
                }
            }
        }
        ResponseCookie cookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        logger.info("Logout successful");
        return ResponseEntity.ok(Map.of("message", "Logged out"));
    }
}
