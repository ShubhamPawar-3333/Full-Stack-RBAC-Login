package com.portfolio.rbac.RbacApplication.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @GetMapping("/hello")
    public String helloUser() {
        return "Hello, User! Your dashboard is ready to roll.";
    }
}
