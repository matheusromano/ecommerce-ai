package com.ecommerceai.authservice.config;

import com.ecommerceai.authservice.security.UserDetailsImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component("userSecurity")
@Slf4j
public class UserSecurity {

    public boolean isOwner(UUID userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        boolean isOwner = userDetails.getId().equals(userId);

        log.debug("Checking ownership: user {} for resource {}, result: {}",
                userDetails.getId(), userId, isOwner);

        return isOwner;
    }
}