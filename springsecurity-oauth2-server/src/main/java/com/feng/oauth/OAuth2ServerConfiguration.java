package com.feng.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 * @Author menglei.feng
 * @Description 配置授权服务器
 * @Date 2021/12/29 下午9:54
 * @Version 1.0
 **/
@Configuration
@EnableAuthorizationServer //开启授权服务器
public class OAuth2ServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 我们配置了使用数据库来维护客户端信息。虽然在各种Demo中我们经常看到的是在内存中维护客户
     * 但是，对于实际的应用我们一般都会用数据库来维护这个信息，甚至还会建立一套工作流来允许客
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients()
                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(),
                jwtTokenEnhancer()));
        endpoints.approvalStore(approvalStore())
                .authorizationCodeServices(authorizationCodeServices())
                .tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                .authenticationManager(authenticationManager);
    }

    /**
     * 使用 JDBC数据库方式来保存授权码
     *
     * @return
     */
    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    /**
     * 使用 JWT存储
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtTokenEnhancer());
    }

    /**
     * 使用 JDBC数据库方式来保存用户的授权批准记录
     *
     * @return
     */
    @Bean
    public JdbcApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }

    /**
     * 自定义的Token增强器，把更多信息放入Token中
     *
     * @return
     */
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }

    /**
     * 配置
     * JWT使用非对称加密方式来验证
     *
     * @return
     */
    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                new ClassPathResource("spring-jwt.jks"), "abc123".toCharArray()
        ); // abc123 为 password
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
        return converter;
    }

    /**
     * 配置登录页面的视图信息（其实可以独立一个配置类，这样会更规范）
     */
    @Configuration
    static class MvcConfig implements WebMvcConfigurer {
        @Override
        public void addViewControllers(ViewControllerRegistry registry) {
            registry.addViewController("login").setViewName("login");
        }
    }
}
