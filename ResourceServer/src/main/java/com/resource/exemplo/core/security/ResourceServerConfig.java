package com.resource.exemplo.core.security;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.anyRequest().authenticated()
			.and()
			.cors().and()
			.oauth2ResourceServer().jwt();
	}
	
	@Bean
	public JwtDecoder jwtDecoder() {
		var secretKey = new SecretKeySpec("89a7sd89f7as98f7dsa98fds7fd89sasd9898asdf98s".getBytes(), "HmacSHA256");
		return NimbusJwtDecoder.withSecretKey(secretKey).build();
	}
	
	
	/*  ***Configurações de Segurança para utilizar HttpBasic***
	
	//Configurando em memoria, usuario e senha que vai ter acesso ao sistema (poderia vir do banco de dados)
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("mauricio")
				.password(passwordEncoder().encode("123"))
				.roles("ADMIN")
			.and()
			.withUser("joao")
				.password(passwordEncoder().encode("123"))
				.roles("ADMIN");
	}
	/* --------------------------------------------------------------------- -------------------------*/
	
	/*
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic()
			.and()
			.authorizeRequests()
				.antMatchers("/v1/exemplo/**").permitAll()//permite o acesso a esse endpoint sem estar autenticado
				.anyRequest().authenticated() //autoriza apenas requisições autenticada
			
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)//Não manda kukies de cessão
		
			.and()
				.csrf().disable(); //desabilita csrf
	}
	
	*/
	
	/* ------------------------ Configurando PasswordEncoder ---------------------- */
	
	/*
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	/* --------------------------------------------------        --------------------*/
	

}
