package telran.security.accounting.service;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.security.accounting.Account;
import telran.security.accounting.IAccounting;
import telran.security.accounting.repository.IAccountingMongoRepository;

@Service
public class AccountingMongo implements IAccounting{
@Autowired
IAccountingMongoRepository accountsRepo;

@Override
public String getPassword(String username) {
	Account account=accountsRepo.findById(username).orElse(null);
	return account==null?null:account.getPassword_hash();
}

@Override
public String[] getRoles(String username) {
	Account account=accountsRepo.findById(username).orElse(null);
	if(account==null)
		return null;
	Set<String> setRoles=account.getRoles();
	return setRoles.stream().map(x->"ROLE_"+x)
			.toArray((x)->new String[setRoles.size()]);
}

}
