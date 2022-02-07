package com.janek.jwt.auth.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.janek.jwt.auth.PrincipalDetails;
import com.janek.jwt.model.User;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있다.
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		try {
			/*
			 * BufferedReader br = request.getReader();
			 * 
			 * String input = null; while ((input = br.readLine()) != null) {
			 * System.out.println(input); }
			 */
			
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			// request.getInputStream() : username과 password 데이터가 들어있다.
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// PrincipalDetailService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴된다.
			// = DB에 있는 username과 password가 일치한다.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			// authentication 객체는 session 영역에 저장됨 => 로그인이 되었다는 것
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("로그인 완료됨" + principalDetails.getUser().getUsername());	// 로그인이 정상적으로 됨
			System.out.println("========================================");
			// authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return해주는 것
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
			// JWT 토큰을 사용하면서 세션을 만들 이유가 없다.(단지 권한 처리 때문에 session 사용)
			
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
		
		/*
		 * 1. username, password 요청
		 * 
		 * 2. 정상적인 로그인 시도(authenticationManager)라면 PrincipalDetailService가 호출되어 loadUserByUsername() 함수 실행 
		 * 
		 * 3. PrincipalDetails를 세션에 담는다.(권한 관리를 위해)
		 * 
		 * 4. JWT 토큰을 만들어서 응답
		*/
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었을 경우 successfulAuthentication 함수 실행
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행 : 인증 완료");
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		// RSA 방식이 아닌 Hash 암호 방식
		String jwtToken = JWT.create()
				.withSubject("토큰")
				.withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));

		response.addHeader("Authorization", "Bearer " + jwtToken);
	}
}
