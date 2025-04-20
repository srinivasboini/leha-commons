package io.github.srinivasboini.common.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("org.leha.security")
@Data
public class AccessControlConfigurationProperties {
}
