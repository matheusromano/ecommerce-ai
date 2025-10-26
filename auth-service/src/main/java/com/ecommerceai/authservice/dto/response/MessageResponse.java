package com.ecommerceai.authservice.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MessageResponse {
    private String message;
    private LocalDateTime timestamp;

    public static MessageResponse of(String message) {
        return MessageResponse.builder()
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
