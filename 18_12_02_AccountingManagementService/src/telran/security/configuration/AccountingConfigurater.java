package telran.security.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class AccountingConfigurater extends

WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http)throws Exception{
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests().anyRequest().authenticated();
	}

}