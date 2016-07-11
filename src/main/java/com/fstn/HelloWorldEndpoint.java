package com.fstn;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Component
@Path("/hello")
public class HelloWorldEndpoint {

    @GET
    @Path("/login")
    public String login() {
        SecurityContextHolder.getContext()
                             .setAuthentication(
                                 new UsernamePasswordAuthenticationToken("user", "user",
                                                                         AuthorityUtils.commaSeparatedStringToAuthorityList(
                                                                             "ROLE_USER")));
        return "login ok";
    }

    @GET
    @Path("/test")
    public String test() {
        if(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            return "hey you are logged";
        }else{
            return "bad";
        }
    }

}