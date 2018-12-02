package telran.security.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static telran.security.dto.AccountingApiConstants.*;
import static telran.security.dto.AccountRoles.*;

@Configuration
public class AccountingConfigurater extends

WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http)throws Exception{
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests().antMatchers(ADD_ROLE).hasRole(ADMIN);
		http.authorizeRequests().antMatchers(REMOVE_ROLE).hasRole(ADMIN_CLEANER);
		http.authorizeRequests().antMatchers(REVOKE_ACCOUNT, ACTIVATE_ACCOUNT).hasRole(ADMIN_UPDATER);
		http.authorizeRequests().antMatchers(ADD_ACCOUNT).hasAnyRole(ADMIN, ADMIN_MANAGER);
		http.authorizeRequests().antMatchers(REMOVE_ACCOUNT).hasAnyRole(ADMIN_CLEANER, ADMIN_MANAGER);
		http.authorizeRequests().antMatchers(UPDATE_PASSWORD).hasAnyRole(ADMIN_MANAGER, ADMIN_UPDATER);
	}

}
