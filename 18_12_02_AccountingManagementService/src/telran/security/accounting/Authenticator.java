package telran.security.accounting;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class Authenticator implements UserDetailsService {

	@Autowired
	IAccounting accounting;
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		String passwordHash=accounting.getPassword(username);
		if(passwordHash==null)
			throw new UsernameNotFoundException("");
		return new User(username, passwordHash, AuthorityUtils.createAuthorityList(accounting.getRoles(username)));
	}

}
