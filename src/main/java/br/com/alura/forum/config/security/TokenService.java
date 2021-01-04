package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {
	@Value("${forum.jwt.expiration}")
	private String expiration;
	
	@Value("${forum.jwt.secret}")
	private String secretKey;
	
	public String gerarToken(Authentication authentication) {
		Usuario usuario = (Usuario)authentication.getPrincipal();
		Date now = new Date();
		Date dataExpiracao = new Date(now.getTime() + Long.parseLong(expiration));
		return Jwts.builder()
				.setIssuer("API DO FORÚM DA ALURA")
				.setSubject(usuario.getId().toString())
				.setIssuedAt(now)
				.setExpiration(dataExpiracao)
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
	}

	public boolean validaToken(String token) {
		try {
			Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public Long getIdUsuario(String token) {
		Claims body = Jwts.parser().setSigningKey(this.secretKey).parseClaimsJws(token).getBody();
		return Long.parseLong(body.getSubject());
	}
	
}
