package io.github.srinivasboini.common.security;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.ArrayList;
import java.util.List;

import io.github.srinivasboini.common.Role;

@Getter
@Setter
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@ToString
public class UserContext {

    final String username ;
    @Builder.Default
    final List<Role> roles = new ArrayList<>() ;
    @Setter
    String location;
    @Setter
    String jwtToken ;

    String email;
    String subject ;

}
