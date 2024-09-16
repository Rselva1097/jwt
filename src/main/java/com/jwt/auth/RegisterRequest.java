package com.jwt.auth;

import com.jwt.user.Role;
import lombok.*;
import lombok.experimental.FieldDefaults;

@FieldDefaults(level = AccessLevel.PRIVATE)
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    String firstname;
    String lastname;
    String email;
    String password;
    Role role;

}
