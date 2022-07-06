package io.tacsio.security.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

@Component
@ConfigurationProperties(prefix = "security.jwt")
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private int tokenExpirationDays;

    public JwtConfig() {
    }

    public String getAuthorizationHeader() {
        return "Authorization";
    }

    public String getAuthoritiesClaim() {
        return "authorities";
    }

    public String getTokenFormat(String token) {
        return String.format("%s %s", tokenPrefix, token);
    }

    public Date getTokenExpiration() {
        return Date.from(LocalDate.now().plusDays(tokenExpirationDays)
                .atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public int getTokenExpirationDays() {
        return tokenExpirationDays;
    }

    public void setTokenExpirationDays(int tokenExpirationDays) {
        this.tokenExpirationDays = tokenExpirationDays;
    }

}