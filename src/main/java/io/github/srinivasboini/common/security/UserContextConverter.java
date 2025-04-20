package io.github.srinivasboini.common.security;


import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import io.github.srinivasboini.common.Role;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Optional;


@Slf4j
@RequiredArgsConstructor
public class UserContextConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtAuthorizationConverter jwtAuthorizationConverter ;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {

        UserContext userContext = convertToCurrentUser(jwt) ;
        log.info("user :{} is created from incoming JWT", userContext);
        Collection<GrantedAuthority> authorities = jwtAuthorizationConverter.convert(jwt) ;
        assert authorities != null;
        authorities
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(Role::fromString)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .forEach(e -> userContext.getRoles().add(e));
        return new UsernamePasswordAuthenticationToken(userContext,jwt,authorities) ;

    }


    private UserContext convertToCurrentUser(Jwt jwt){
        String username = jwt.getClaimAsString("name") ;
        String subject  = jwt.getClaimAsString("sub") ;
        String email = jwt.getClaimAsString("email") ;

        return UserContext.builder()
                .username(username)
                .jwtToken(jwt.getTokenValue())
                .email(email)
                .subject(subject)
                .build() ;
    }
}
