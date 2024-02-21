package github.jaemin.book.secutiry;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@PropertySource("security.properties")
@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("jwt.secret_key")
    private final String SECRET_KEY;
    @Value("jwt.expire_time")
    private final long EXPIRE_TIME;

    public String generateToken(Authentication authentication) {
        return generateToken(authentication.getName(), authentication.getAuthorities());
    }

    public String generateToken(String userName, Collection<? extends GrantedAuthority> authorities) {
        return Jwts.builder().setSubject(userName).claim("role", authorities.stream().findFirst().orElseThrow().toString())
                .setExpiration(getExpireDate()).signWith(getKey(), SignatureAlgorithm.HS256).compact();
    }

    public Authentication getAuthentication(String accessToken) {
        return new UsernamePasswordAuthenticationToken(getUsername(accessToken), "", createAuthorityList(getRole(accessToken)));
    }

    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    private JwtParser getParser() {
        return Jwts.parserBuilder()
                .setSigningKey(Base64.getDecoder().decode(SECRET_KEY))
                .build();
    }

    private SecretKey getKey() {
        return new SecretKeySpec(Base64.getDecoder().decode(SECRET_KEY), 0, SECRET_KEY.length(), SignatureAlgorithm.HS256.getValue());
    }

    public boolean validateToken(String accessToken) {
        if (accessToken == null) {
            return false;
        }

        try {
            return getParser()
                    .parseClaimsJws(accessToken)
                    .getBody()
                    .getExpiration()
                    .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private String getUsername(String accessToken) {
        return getParser()
                .parseClaimsJws(accessToken)
                .getBody()
                .getSubject();
    }

    private String getRole(String accessToken) {
        return getParser()
                .parseClaimsJws(accessToken)
                .getBody()
                .get("role", String.class);

    }

    private Date getExpireDate() {
        Date now = new Date();
        return new Date(now.getTime() + EXPIRE_TIME);
    }
}
