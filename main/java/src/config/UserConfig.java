package src.config;

import jwt.JwtUserScopes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import src.model.UserPJO;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserConfig implements UserDetails {
    private UserPJO user;

    public UserConfig(UserPJO user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        if (user.isAdmin()) {
            authorities.add(new SimpleGrantedAuthority(JwtUserScopes.ADMIN));
        } else if (user.isUserManager()) {
            authorities.add(new SimpleGrantedAuthority(JwtUserScopes.USER_MANAGER));
        } else {
            authorities.add(new SimpleGrantedAuthority(JwtUserScopes.WAREHOUSE_MANAGER));
        }

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}