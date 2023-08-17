package com.coding404.jwt.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.coding404.jwt.security.config.JWTService;
import com.coding404.jwt.user.MyUserDetails;

public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter { //필터를 상속받음

	
	
	//attemptAuthentication을 오버라이딩 하면
	//클라이언트에서 포스트형태로 /login 로 들어오면 실행됩니다.
	
	private AuthenticationManager authenticationManager;
	
	//생성될떄 AuthenticationManager를 생성자 매개변수로 받습니다.
	public CustomLoginFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		System.out.println("=========attemptAuthentication실행됨========>");
		
		//로그인처리 - 로그인 시도하는 사람은 반드시 form타입으로 전송(이건 개발자가 방식을 정하는 것 JSON형식도 가능 + 제이슨맵핑처리)
		//1. username, password를 받음
		//
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		
		System.out.println(username);
		System.out.println(password);
		
		//스프링 시쿠리티가 로그인에 사용하는 토큰객체
		UsernamePasswordAuthenticationToken token =
				new UsernamePasswordAuthenticationToken(username, password);
		
		//AuthenticationManager가 실행되면 UserDetailService의 loadUserByUsername 실행
		Authentication authentication = authenticationManager.authenticate(token);
		
		System.out.println("내가 실행되었다는 것은 로그인 성공!!" + authentication);
		//이거 안나오면 로그인실패
		
		
		
		
		
		return authentication; //여기서 반환되는 return은 시큐리티 세션이 가져가서 new 시큐리티세션(new 인증객체(new 유저객체))형태로 저장시킴
	}

	//로그인 성공 후에 실행되는 메서드
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
	
		System.out.println("=======로그인 성공 핸들러 실행됨========");
		
		//토큰발행 헤더에 담고 클라이언트로 전달
	
		System.out.println("로그인 성공 이후 인증객체: " + authResult);
		
		MyUserDetails principal = (MyUserDetails)authResult.getPrincipal();
		
		String token = JWTService.createToken(principal.getUsername()); //회원 아이디
		
		response.setContentType("text/html; charset=UTF-8;");
		response.setHeader("Authorization", "Bearer " + token);
		response.getWriter().println("로그인 성공(아이디)" + principal.getUsername());
	}

	//로그인 실패 후에 실행되는 메서드
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		System.out.println("=======로그인 실패 핸들러 실행됨========");
		
		response.setContentType("text/html; charset=UTF-8;");
	
		//response.getWriter().println("응답할내용");
		response.sendError(500, "아이디 비밀번호를 확인하세요");
	} 
	
	
	

}
