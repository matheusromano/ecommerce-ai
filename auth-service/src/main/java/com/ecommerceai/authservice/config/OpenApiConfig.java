//package com.ecommerceai.authservice.config;
//
//import io.swagger.v3.oas.annotations.OpenAPIDefinition;
//import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
//import io.swagger.v3.oas.annotations.info.Contact;
//import io.swagger.v3.oas.annotations.info.Info;
//import io.swagger.v3.oas.annotations.info.License;
//import io.swagger.v3.oas.annotations.security.SecurityScheme;
//import io.swagger.v3.oas.annotations.servers.Server;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//@OpenAPIDefinition(
//        info = @Info(
//                title = "E-commerce Auth Service API",
//                version = "1.0.0",
//                description = "Authentication and Authorization Service for E-commerce Platform with AI-powered Design Generation",
//                contact = @Contact(
//                        name = "E-commerce Team",
//                        email = "support@ecommerce.com",
//                        url = "https://ecommerce.com"
//                ),
//                license = @License(
//                        name = "Apache 2.0",
//                        url = "https://www.apache.org/licenses/LICENSE-2.0.html"
//                )
//        ),
//        servers = {
//                @Server(
//                        url = "http://localhost:8081",
//                        description = "Development Server"
//                ),
//                @Server(
//                        url = "https://api.ecommerce.com",
//                        description = "Production Server"
//                )
//        }
//)
//@SecurityScheme(
//        name = "bearer-jwt",
//        type = SecuritySchemeType.HTTP,
//        scheme = "bearer",
//        bearerFormat = "JWT",
//        description = "JWT Authentication Token"
//)
//public class OpenApiConfig {
//}