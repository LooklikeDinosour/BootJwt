package com.coding404.jwt.security.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
	
	
	

}