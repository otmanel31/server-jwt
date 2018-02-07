package com.bfwg.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.bfwg.security.auth.AuthenticationFailureHandler;
import com.bfwg.security.auth.AuthenticationSuccessHandler;
import com.bfwg.security.auth.LogoutSuccess;
import com.bfwg.security.auth.RestAuthenticationEntryPoint;
import com.bfwg.security.auth.TokenAuthenticationFilter;
import com.bfwg.service.impl.CustomUserDetailsService;

/**
 * Created by fan.jin on 2016-10-19.
 */

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) // pour les préauthorize .... 
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${jwt.cookie}") // va le chercher ds le fichier properties
  private String TOKEN_COOKIE;

  @Bean
  public TokenAuthenticationFilter jwtAuthenticationTokenFilter() throws Exception {
    return new TokenAuthenticationFilter();
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Autowired
  private CustomUserDetailsService jwtUserDetailsService;

  @Autowired
  private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

  @Autowired
  private LogoutSuccess logoutSuccess;

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder authenticationManagerBuilder)
      throws Exception {
    authenticationManagerBuilder.userDetailsService(jwtUserDetailsService)
        .passwordEncoder(passwordEncoder());

  }

  @Autowired
  private AuthenticationSuccessHandler authenticationSuccessHandler;

  @Autowired
  private AuthenticationFailureHandler authenticationFailureHandler;

  /// config de la securite 
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable() //ignoringAntMatchers("/api/login", "/api/signup") // desactive csrf 
    	//.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and() // son propre mecanisme pour pas que sa bloque
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and() // pas de session
        .exceptionHandling().authenticationEntryPoint(restAuthenticationEntryPoint).and() // au cas ou erreur, restAu..entypoint 
        .addFilterBefore(jwtAuthenticationTokenFilter(), BasicAuthenticationFilter.class) // ajout filtre ds liste filtre spring security avant le basic authneitcaiton
        .authorizeRequests().anyRequest().authenticated().and().formLogin().loginPage("/api/login")  // authorize tte les req auithentifier et form login pour page de login
        .successHandler(authenticationSuccessHandler).failureHandler(authenticationFailureHandler) // success objet a appeler en cas de succes ou fail
        .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/api/logout"))  // cas de logout, sur url logout success handler pour effevcer le cookie en bas
        .logoutSuccessHandler(logoutSuccess).deleteCookies(TOKEN_COOKIE);//  <===== ----------------- ---------------------   ------------------------  ----------<= |

  }
  
  // disbale cors globally
  @Bean
  public WebMvcConfigurer corsConfigurer() {
	  return new WebMvcConfigurerAdapter() {
          @Override
          public void addCorsMappings(CorsRegistry registry) {
              registry.addMapping("/**")
              	.allowedOrigins("http://localhost:4200")
      			.allowedMethods("PUT", "DELETE", "OPTION", "GET", "POST")
      			.allowedHeaders("Origin, X-Requested-With", "Content-Range", "Content-Disposition", "Content-Type", "Authorization", "Bearer",
      					"X-CSRF-TOKEN", "X-XSRF-TOKEN")
      			.exposedHeaders("Origin, X-Requested-With", "Content-Range", "Content-Disposition", "Content-Type", "Authorization","Bearer",
      					"X-CSRF-TOKEN", "X-XSRF-TOKEN")
      			.allowCredentials(true);
          }
      };
  }

}
