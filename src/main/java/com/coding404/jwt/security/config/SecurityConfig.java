package com.coding404.jwt.security.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.coding404.jwt.security.filter.CustomLoginFilter;
import com.coding404.jwt.security.filter.FilterOne;
import com.coding404.jwt.security.filter.FilterTwo;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	
	//비밀번호 암호화객체
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		//기본로그인 방식, 세션, 베이직인증, csrf토큰 전부 사용 x
		http.csrf().disable();
		
		http.formLogin().disable();// form기반 로그인을 사용 x / rest기반 사용할거임
		http.httpBasic().disable(); //Authorization: 아이디 형식으로 넘어오는 basic인증을 사용x
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션인증 기반을 사용x, JWT 사용해서 인증		
	
		http.authorizeHttpRequests( auth -> auth.anyRequest().permitAll()); //모든 요청은 전부 허용ㄴ
		
		//1. 크로스오리진 필터 생성 cors
		http.cors(Customizer.withDefaults());
		
		
		//2. 필터체이닝 연습 (filterOne.java 먼저 생성 내용 구성후 2. 작성)
		//http.addFilter(new FilterOne()); // addfilter는 시큐리티 타입의 필터를 등록할 때 사용
		
		//http.addFilterBefore(new FilterOne(), UsernamePasswordAuthenticationFilter.class); //뒷부분은 시큐리티 타입의 필터
		//http.addFilterBefore(new FilterTwo(), FilterOne.class); //필터원보다 이전에 실행되게
		//http.addFilterAfter(new FilterTwo(), FilterOne.class); //필터원보다 이후에 실행됨.
		
		//3. 로그인 시도에 AuthenticationManager 필요
		//++UserDetailService객체 and PasswordEncoder가 반드시 필요
		
		AuthenticationManager authenticationManager =
				authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
		
		System.out.println(authenticationManager);
		
		//4. 로그인필터를 등록
		//http.addFilterBefore(new CustomLoginFilter(), UsernamePasswordAuthenticationFilter.class);
		http.addFilter(new CustomLoginFilter(authenticationManager));
		
		
		
		
		return http.build();
	}
	
	// 로그인 시도에 필요한 AuthenticationManager객체
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}
	
	
	
	//크로스 오리진 필터
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*")); // 모든 요청주소 허용
		configuration.setAllowedMethods(Arrays.asList("*")); // 모든 요청메서드 허용
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration); // 모든 요청에 대해 적용
		return source;
	}
}
