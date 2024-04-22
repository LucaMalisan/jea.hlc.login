package src.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import src.model.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserConfig implements UserDetails {
    private User user;

    public UserConfig(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        if (user.isAdmin()) {
            authorities.add(new SimpleGrantedAuthority("admin"));
        } else if (user.isUserManager()) {
            authorities.add(new SimpleGrantedAuthority("user_manager"));
        } else {
            authorities.add(new SimpleGrantedAuthority("warehouse_manager"));
        }

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return String.format("%s-%s", user.getName().toLowerCase(), user.getFirstName().toLowerCase());
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