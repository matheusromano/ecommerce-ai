package com.ecommerceai.authservice.mapper;

import com.ecommerceai.authservice.dto.response.UserResponse;
import com.ecommerceai.authservice.model.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserResponse toUserResponse(User user);
}
