package com.techprimers.security.springsecurityauthserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@EnableResourceServer
@Configuration
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {
//
//    @Autowired
//    private AuthenticationManager authenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.requestMatchers().antMatchers("/login", "/oauth/authorize").and().authorizeRequests().anyRequest()
                .authenticated().and().formLogin().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // auth.parentAuthenticationManager(authenticationManager)
        // .inMemoryAuthentication()
        // .withUser("Peter")
        // .password("peter")
        // .roles("USER");

        auth.ldapAuthentication().userDnPatterns("uid={0},ou=people").groupSearchBase("ou=people").contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org").and().passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder()).passwordAttribute("userPassword");

    }
}
