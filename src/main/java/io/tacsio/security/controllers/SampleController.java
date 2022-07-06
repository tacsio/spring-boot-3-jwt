package io.tacsio.security.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SampleController {

    @GetMapping("/up")
    public String up() {
        return "It's UP";
    }

    @GetMapping("/secured")
    public String secured(@AuthenticationPrincipal String username) {
        return "Hello " + username;
    }
}
