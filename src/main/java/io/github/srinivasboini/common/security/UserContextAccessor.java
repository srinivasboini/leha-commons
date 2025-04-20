package io.github.srinivasboini.common.security;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class UserContextAccessor {

    public UserContext getUserContext(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication() ;
        if(!(authentication.getPrincipal() instanceof UserContext)){
            throw new AccessDeniedException("No Logged user found. Access is denied") ;
        }

        return (UserContext) authentication.getPrincipal() ;
    }
}
