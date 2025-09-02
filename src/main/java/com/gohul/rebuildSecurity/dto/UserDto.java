package com.gohul.rebuildSecurity.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class UserDto {

    @NotBlank
    @Min(value = 4, message = "Username should has at least 4 characters")
    @Max(value = 15, message = "Username should has at most 15 characters")
    private String username;
    @Email
    @NotBlank
    private String email;
    @NotBlank
    @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*\\d).{8,}$", message = "Password must be at least 8 characters long and contain both letters and digits.")
    private String password;

}
