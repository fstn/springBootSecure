/*
 * Copyright 2012-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fstn;

import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;

import javax.inject.Named;
import javax.ws.rs.ApplicationPath;

@SpringBootApplication
public class SampleSecureApplication
{

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter
    {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            SimpleCORSFilter corsFilter = new SimpleCORSFilter();
            http
                .csrf().disable()
                .addFilterBefore(corsFilter,ChannelProcessingFilter.class)
                .authorizeRequests()
                .antMatchers("/rest/hello/login").permitAll()
                .anyRequest().authenticated();
        }
    }

    @Named
    @ApplicationPath("/rest")
    public static class JerseyConfig extends ResourceConfig
    {

        public JerseyConfig() {
            packages("com.fstn");
            register(HelloWorldEndpoint.class);
        }
    }


    public static void main(String[] args) {
        SpringApplication.run(SampleSecureApplication.class, args);
    }
}