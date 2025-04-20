package io.github.srinivasboini.common;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@AllArgsConstructor
@Getter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public enum Role {

    ROLE_ADMIN("APP.BUSN_ADMIN"),
    ROLE_MAKER("APP.BUSN_MAKER"),
    ROLE_CHECKER("APP.BUSN_CHECKER") ;
    String name ;


    public static Optional<Role> fromString(String value) {
        for (Role role : Role.values()) {
            if (role.name.equals(value)) {
                return Optional.of(role);
            }
        }
        return Optional.empty() ;
    }

}
