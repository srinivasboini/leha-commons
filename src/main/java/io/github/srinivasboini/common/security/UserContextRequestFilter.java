package io.github.srinivasboini.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import io.github.srinivasboini.common.Role;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public class UserContextRequestFilter extends OncePerRequestFilter {



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(!isUserAuthenticated()){
            String authUserName = request.getHeader("X-Auth-Subject") ;
            String authLocation = request.getHeader("X-Auth-Location") ;
            String authRoles = request.getHeader("X-Auth-Roles") ;
            String authToken = request.getHeader("X-Auth-Token") ;

            List<Role> roles = Stream.
                    of(authRoles.split(","))
                    .filter(StringUtils::isNotBlank)
                    .map(Role::fromString)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .toList();

            UserContext userContext = UserContext
                    .builder()
                    .username(authUserName)
                    .location(authLocation)
                    .jwtToken(authToken)
                    .roles(roles)
                    .build() ;

            SecurityContextHolder
                    .getContext()
                    .setAuthentication( new UsernamePasswordAuthenticationToken(userContext, null, getAuthorities(userContext)));

        }

        filterChain.doFilter(request, response);


    }

    private List<Role> convertToRoles(List<String> roles) {
        return roles.stream().map(Role::valueOf).collect(Collectors.toList());
    }

    private boolean isUserAuthenticated(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return  authentication != null
                && authentication.isAuthenticated()
                && authentication.getPrincipal() !=null
                && authentication.getPrincipal() instanceof UserContext ;
    }

    private List<GrantedAuthority> getAuthorities(UserContext userContext) {
        return  userContext
                .getRoles()
                .stream()
                .map(Enum::toString)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
