package com.omid.security.jwtutil;

import com.omid.security.DAO.Entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JWTokenUtility {

    static final String CLAIM_KEY_USERNAME = "sub";
    static final String CLAIM_KEY_AUDIENCE = "aud";
    static final String CLAIM_KEY_CREATED = "iat";

    private static String secret = "123AlA!aLa456";
    private static long expiration =600l ;


    public static String buildJWT(String username , String password ) {
        RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
        System.out.println("RSA hash code... " + rsaJsonWebKey.hashCode() + rsaJsonWebKey.getPrivateKey());

        JwtClaims claims = new JwtClaims();
        claims.setSubject("Authentication"); // the subject/principal is whom the token is about

        claims.setClaim("username" , username);
        claims.setClaim("password" , password);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (JoseException ex) {
         //   Logger.getLogger(JWTAuthFilter.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Claim:\n" + claims);
        System.out.println("JWS:\n" + jws);
        System.out.println("JWT:\n" + jwt);

        return jwt;
    }

    public static String buildJWTAuthentication(String username , String password ,String roles ) {
        RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
        System.out.println("RSA hash code... " + rsaJsonWebKey.hashCode() + rsaJsonWebKey.getPrivateKey());

        JwtClaims claims = new JwtClaims();
        claims.setSubject("Authentication"); // the subject/principal is whom the token is about

        claims.setClaim("username" , username);
        claims.setClaim("password" , password);
        claims.setClaim("roles" , roles);


        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaJsonWebKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);


        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (JoseException ex) {
         //   Logger.getLogger(JWTAuthFilter.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println("Claim:\n" + claims);
        System.out.println("JWS:\n" + jws);
        System.out.println("JWT:\n" + jwt);

        return jwt;
    }

    public static String generateJWTAuthentication (String username , String password) {

        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate);


         Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("subject" ,"Authentication"); // the subject/principal is whom the token is about

        claims.put("username", username);
        claims.put("password", password);

        return "Bearer " +Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setAudience("web")
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

    }

    public static String generateJWTAuthorization (String username , String password ,String roles ) {

        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate);


        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("subject" ,"Authorization");

        claims.put("username", username);
        claims.put("password", password);
        claims.put("roles", roles);

        return "Bearer "+ Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setAudience("web")
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

    }

    public static <T> T getClaimFromToken(String token, String claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        T t = null;

        if (claimsResolver.equals("getSubject"))
            t = (T) claims.getSubject();
        if (claimsResolver.equals("getIssuedAt"))
            t = (T) claims.getIssuedAt();
        if (claimsResolver.equals("getExpiration"))
            t = (T) claims.getExpiration() ;
        if (claimsResolver.equals("ticketNumber"))
            t = (T) claims.get("ticketNumber") ;
        if (claimsResolver.equals("password"))
            t = (T) claims.get("password") ;
        if (claimsResolver.equals("roles"))
            t = (T) claims.get("roles") ;
        return t ;

    }

    private static Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    private static Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private static Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }

    //TODO : this method define the device client is using such is phone , pc , ...
    /*private String generateAudience(Device device) {
        String audience = AUDIENCE_UNKNOWN;
        if (device.isNormal()) {
            audience = AUDIENCE_WEB;
        } else if (device.isTablet()) {
            audience = AUDIENCE_TABLET;
        } else if (device.isMobile()) {
            audience = AUDIENCE_MOBILE;
        }
        return audience;
    }*/


    private Boolean ignoreTokenExpiration(String token) {
        String audience = getAudienceFromToken(token);
        return ("tablet".equals(audience) || "mobile".equals(audience));
    }


    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getIssuedAtDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && (!isTokenExpired(token) || ignoreTokenExpiration(token));
    }

    public String refreshToken(String token) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate);

        final Claims claims = getAllClaimsFromToken(token);
        claims.setIssuedAt(createdDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public static Boolean validateToken(String token, User userDetails) {

        final String username = getUsernameFromToken(token);
        final Date created = getIssuedAtDateFromToken(token);
        final Date expiration = getExpirationDateFromToken(token);
        return (
                username.equals(userDetails.getEmail())
                        && !isTokenExpired(token)
                        //&& !isCreatedBeforeLastPasswordReset(created, userDetails.getLastPasswordResetDate())
        );
    }

    private static Date calculateExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 1000);
    }


    public String createTransactionToken(Map<String , Object> claims){
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();

    }

    public static String getUsernameFromToken(String token) {

        return getClaimFromToken(token, "getSubject");
    }

    public static String getPasswordFromToken(String token) {

        return getClaimFromToken(token, "password");
    }

    public static String getRolesFromToken(String token) {

        return getClaimFromToken(token, "roles");
    }


    public static Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, "getIssuedAt");
    }

    public static Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, "getExpiration");
    }

    public String getAudienceFromToken(String token) {
        return getClaimFromToken(token, "getAudience");
    }


}
