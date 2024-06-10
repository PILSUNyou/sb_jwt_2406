package com.example.jwt;

import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtApplicationTests {

	@Autowired
	private JwtPrivider jwtProvider;

	@Value("${custom.jwt.secretKey}")
	private String secretKeyPlain;

	@Test
	@DisplayName("시크릿 키 존재 여부 체크")
	void Test1() {
		assertThat(secretKeyPlain).isNotNull();
	}

	@Test
	@DisplayName("secretKeyPlain을 이용하여 암호화 알고리즘 SecretKey 객체 생성")
	void Test2() {
		String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());
		// 시크릿키를 64비트 쪼개어 다시 만들고, 시크릿키 타입을 만들고 객체를 생성 한다.
		SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
		// 객체가 정상적으로 생성이 됐는지 확인하는 작업
		assertThat(secretKey).isNotNull(); // NULL값인지 확인
	}

	@Test
	@DisplayName("jwtProvider 객체를 활용하여 SercetKey 객체 생성")
	void Test3() {
		SecretKey secretKey = jwtProvider.getScretKey();
		assertThat(secretKey).isNotNull();
	}

	@Test
	@DisplayName("SecretKey 객체 생성을 한 번만 하도록 처리")
	void Test4() {
		SecretKey secretKey1 = jwtProvider.getScretKey();
		SecretKey secretKey2 = jwtProvider.getScretKey();
		assertThat(secretKey1 == secretKey2).isTrue();
	}

}