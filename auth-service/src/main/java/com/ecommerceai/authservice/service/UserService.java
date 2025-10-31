package com.ecommerceai.authservice.service;


import com.ecommerceai.authservice.dto.response.UserResponse;
import com.ecommerceai.authservice.exception.ResourceNotFoundException;
import com.ecommerceai.authservice.mapper.UserMapper;
import com.ecommerceai.authservice.model.User;
import com.ecommerceai.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return userMapper.toUserResponse(user);
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(userMapper::toUserResponse);
    }

    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setDeleted(true);
        user.setDeletedAt(java.time.LocalDateTime.now());
        user.setEnabled(false);

        userRepository.save(user);

        log.info("User soft deleted: {}", userId);
    }
}
