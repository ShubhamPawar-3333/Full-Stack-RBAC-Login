package com.portfolio.rbac.RbacApplication.dto;

import com.portfolio.rbac.RbacApplication.model.Role;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(@NotBlank String username, @NotBlank String password, Role role) {
}
