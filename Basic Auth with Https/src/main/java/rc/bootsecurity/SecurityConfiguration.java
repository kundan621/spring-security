package rc.bootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    	//"ROLE_ADMIN" added in authority as authority takes precedence ovver roles
        auth.inMemoryAuthentication().withUser("admin").password(passwordEncoder().encode("admin123")).roles("ADMIN").authorities("ACCESS_TEST1","ACCESS_TEST2","ROLE_ADMIN")
                .and().withUser("kundan").password(passwordEncoder().encode("@kundan621Kk")).roles("USER")
                .and().withUser("kundan1").password(passwordEncoder().encode("@kundan621Kk1")).roles("MANAGER");
    }
    //note in above case authority is bigger than role, if you want to use role in configure below then role also needs to be added in the authority above

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN") //role is admin so "ROLE_ADMIN" added in authority
                .antMatchers("/management/**").hasAnyRole("MANAGER","ADMIN")
                .antMatchers("/api/public/**").hasAuthority("ACCESS_TEST1").and().httpBasic();
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
