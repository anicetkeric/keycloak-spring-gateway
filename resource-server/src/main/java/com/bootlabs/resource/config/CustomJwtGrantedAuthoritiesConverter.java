package com.bootlabs.resource.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.*;
import java.util.stream.Stream;

/**
 * @see <a href="https://medium.com/@alperkrtglu/spring-oauth2-with-keycloak-moving-from-scope-to-roles-34247f3ff78e">Spring OAuth2 with OIDC: Moving from Scope to Roles</a>
 * Converts the roles from the JWT token to a collection of GrantedAuthority
 */
@Slf4j
public class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ROLES = "roles";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String CLIENT_ID = "gateway-labs";

    private final JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Start with default authorities
        Collection<GrantedAuthority> authorities = new HashSet<>(defaultConverter.convert(jwt));

        // Attempt to extract client-specific roles from resource_access
        extractClientRoles(jwt).stream()
                .map(this::formatRole)
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);

        log.debug("Resolved authorities: {}", authorities);
        return authorities;
    }

    private List<String> extractClientRoles(Jwt jwt) {
        return Optional.ofNullable(jwt.getClaimAsMap(RESOURCE_ACCESS))
                .map(resourceAccess -> resourceAccess.get(CLIENT_ID))
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .map(client -> client.get(ROLES))
                .filter(List.class::isInstance)
                .map(List.class::cast)
                .orElse(Collections.emptyList());
    }

    private String formatRole(String role) {
        return role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role;
    }

    @Override
    public <U> Converter<Jwt, U> andThen(Converter<? super Collection<GrantedAuthority>, ? extends U> after) {
        return Converter.super.andThen(after);
    }
}