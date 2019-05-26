package com.omid.security.jwtutil;

import com.omid.security.DAO.Entity.User;
import com.omid.security.Service.UserService;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;


@Component
@Order(1)
public class JWTAuthFilter extends OncePerRequestFilter {


    @Autowired
    UserService userService;


    @Override
    public void doFilterInternal(HttpServletRequest servletRequest, HttpServletResponse servletResponse, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("request filter invoked...");

        HttpServletRequest requestContext = (HttpServletRequest) servletRequest;
        HttpServletResponse responseContext = (HttpServletResponse) servletResponse;

        String authorizationHeaderVal = requestContext.getHeader("Authorization");
        String authenticationHeaderVal = requestContext.getHeader("Authentication");
        String webSocket = requestContext.getHeader("sec-websocket-key");

        try {
            if (webSocket != null) {
                filterChain.doFilter(requestContext, responseContext);
                return;
            }

            if (!requestContext.getRequestURI().startsWith("/api") ||
                    requestContext.getRequestURI().equals("/api/doLogin")) {
                filterChain.doFilter(requestContext, responseContext);
                return;
            } else if (authenticationHeaderVal != null && authenticationHeaderVal.startsWith("Bearer")) {

                String token = authenticationHeaderVal.split(":")[1];
                String username = JWTokenUtility.getUsernameFromToken(token);
                String password = JWTokenUtility.getPasswordFromToken(token);
                User user = new User();
                user.setUsername(username);

                User jwtUser = userService.getUserByUsername(user);
                final boolean validation = JWTokenUtility.validateToken(token, jwtUser);


                if (validation && username != null && jwtUser != null && jwtUser.getPassword().equals(password)) {
                    if (jwtUser.getRole() != null) {
                        //requestContext.setSecurityContext(new SecurityContextAuthorizer(uriInfo, () -> username, null));
                        String jwt = JWTokenUtility.generateJWTAuthorization(username, password, jwtUser.getRole());

                        responseContext.addHeader("Authorization", jwt);
                        //requestContext.abortWith(Response.ok(jwt).build());
                    } else {
                        //requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
                        Logger.getLogger("Version or roles did not match the token");
                    }
                } else {
                    //requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
                    Logger.getLogger("Version or roles did not match the token");
                }


            } else if (authorizationHeaderVal != null && authorizationHeaderVal.startsWith("Bearer")) {

                String token = authorizationHeaderVal.split(":")[1];

                String username = JWTokenUtility.getUsernameFromToken(token);
                String password = JWTokenUtility.getPasswordFromToken(token);
                String role = JWTokenUtility.getRolesFromToken(token);
                User user = new User();
                user.setUsername(username);


                String[] userRole = role != null ? role.split(",") : null;

                User jwtUser = userService.getUserByUsername(user);
                final boolean subject = JWTokenUtility.validateToken(authorizationHeaderVal.split(" ")[1], jwtUser);

                //final SecurityContext securityContext = requestContext.getSecurityContext();
                if (userRole != null && jwtUser.getPassword().equals(password)) {
                    //  requestContext.setSecurityContext(new SecurityContextAuthorizer(uriInfo, () -> username, userRole));
                    return;
                } else {
                    //      requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
                    Logger.getLogger("Version or roles did not match the token");
                }

            } else {
                System.out.println("No JWT token !");
                responseContext.sendError(800);
                //           responseContext.sendRedirect("/home222");
                return;
                //        requestContext.setProperty("auth-failed", true);
                //       requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            filterChain.doFilter(requestContext, responseContext);
            return;
        } catch (Exception ex) {
            System.out.println("JWT validation failed" + ex);
            //   requestContext.setProperty("auth-failed", true);
            //     requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());

        }


    }

    @Override
    public void destroy() {

    }

    private String validate(String jwt) throws InvalidJwtException {
        String subject = null;
        RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
        System.out.println("RSA hash code... " + rsaJsonWebKey.hashCode());
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            subject = (String) jwtClaims.getClaimValue("sub");
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            e.printStackTrace(); //on purpose
            throw e;
        }

        return subject;
    }

    private String getUsername(String jwt) {
        String username = "";
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireSubject() // the JWT must have a subject claim
                    .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                    .build();
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            username = (String) jwtClaims.getClaimValue("username");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return username;
    }

    private String getPassword(String jwt) {
        String password = "";
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireSubject() // the JWT must have a subject claim
                    .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                    .build();
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            password = (String) jwtClaims.getClaimValue("password");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return password;
    }

    private String[] getRole(String jwt) {
        String[] role = new String[1];
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaKeyProducer.produce();
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireSubject() // the JWT must have a subject claim
                    .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
                    .build();
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            role[0] = (String) jwtClaims.getClaimValue("roles");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return role;
    }


}
