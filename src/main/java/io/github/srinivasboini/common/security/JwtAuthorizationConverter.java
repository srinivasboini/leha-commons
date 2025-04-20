package io.github.srinivasboini.common.security;


import lombok.extern.slf4j.Slf4j;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthorizationConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {

        Collection<?> authorities = (Collection<?>)
                jwt.getClaimAsMap("realm_access")
                        .getOrDefault("roles",Collections.emptyList()) ;
        log.info("authorities extracted {}", authorities) ;

        return authorities
                .stream()
                .map(String::valueOf)
                .map(SimpleGrantedAuthority::new)
                //.filter(Optional::isPresent)
                //.map(Optional::get)
                .collect(Collectors.toList());


    }
}
