package telran.security.accounting.service;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import telran.security.accounting.Account;
import telran.security.accounting.IAccounting;
import telran.security.accounting.repository.IAccountingMongoRepository;

@Service
public class AccountingMongo implements IAccounting{
@Autowired
IAccountingMongoRepository accountsRepo;

@Value("${expiration_period:1}")
int expirationPeriod;

@PostConstruct
public void displayValue() {
	System.out.println(expirationPeriod);
}

@Override
public String getPassword(String username) {
	Account account=accountsRepo.findById(username).orElse(null);
	if((ChronoUnit.DAYS.between(account.getActivationDate(), LocalDate.now()) < expirationPeriod) && !account.isRevoked() && account != null)
		return account.getPassword_hash();
	else return null;
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
