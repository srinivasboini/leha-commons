package io.github.srinivasboini.common.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties(AccessControlConfigurationProperties.class)
@EnableMethodSecurity
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class AccessControlConfiguration {

    private static final String PATTERN = "/users/**";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, OAuth2ResourceServerProperties oAuth2ResourceServerProperties) throws Exception {

        UserContextConverter userContextConverter = new UserContextConverter(new JwtAuthorizationConverter());

        log.info("creating service to service security filter chain");
        return httpSecurity.headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .csrf(CsrfConfigurer::disable)
                .securityMatcher(PATTERN)
                .httpBasic(HttpBasicConfigurer::disable)
                .formLogin(FormLoginConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authRequest -> authRequest.anyRequest().authenticated())
                .addFilterBefore(new UserContextRequestFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .oauth2ResourceServer(oAuth2 ->
                        oAuth2.jwt(jwt -> jwt.jwtAuthenticationConverter(userContextConverter)
                                .decoder(jwtDecoder(oAuth2ResourceServerProperties)))
                )
                .build();

    }

    private JwtDecoder jwtDecoder(OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {

        NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder jwkSetUriJwtDecoderBuilder =
                NimbusJwtDecoder
                        .withJwkSetUri(oAuth2ResourceServerProperties.getJwt().getJwkSetUri());

        Set<SignatureAlgorithm> allowedAlgorithms = oAuth2ResourceServerProperties
                .getJwt()
                .getJwsAlgorithms()
                .stream()
                .map(SignatureAlgorithm::valueOf)
                .collect(Collectors.toSet());
        jwkSetUriJwtDecoderBuilder.jwsAlgorithms(value -> value.addAll(allowedAlgorithms));
        NimbusJwtDecoder jwtDecoder = jwkSetUriJwtDecoderBuilder.build();
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ofMinutes(5))
        ));


        return jwtDecoder;

    }

    @Bean
    public UserContextAccessor userContextAccessor() {
        return new UserContextAccessor();
    }


}
