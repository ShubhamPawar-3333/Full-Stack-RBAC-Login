package com.portfolio.rbac.RbacApplication.dto;

import jakarta.validation.constraints.NotBlank;

public record AuthRequest(@NotBlank String username, @NotBlank String password) {
}
