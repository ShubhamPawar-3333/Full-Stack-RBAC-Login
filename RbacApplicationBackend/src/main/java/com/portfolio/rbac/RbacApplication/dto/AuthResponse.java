package com.portfolio.rbac.RbacApplication.dto;

import com.portfolio.rbac.RbacApplication.model.Role;

public record AuthResponse(String token, Role role) {
}
