package telran.security.accounting.management;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import telran.security.accounting.Account;
import telran.security.accounting.repository.IAccountingMongoRepository;
import telran.security.dto.AccountDto;
import telran.security.dto.ResponseCode;

import static telran.security.dto.ResponseCode.*;


@Service
public class AccoutingService implements IAccountingManagement {
	private static final int N_LAST_PASSWORDS = 3;
	private static final int LENGTH = 8;
	
	@Autowired
	IAccountingMongoRepository accountsRepository;

	@Autowired
	PasswordEncoder encoder;


	@Override
	public ResponseCode addAccount(AccountDto accountDto) {
		if (accountsRepository.existsById(accountDto.getUsername())) {
			System.out.println("Account already exists");
			return USERNAME_EXIST;
		}
		String username = accountDto.getUsername();
		String password = accountDto.getPassword();
		String resultCheck = checkPasswordMatches(password);
		if (resultCheck.length()!=0) {
			System.out.println("Password incorrect. \n"+resultCheck);
			return PASSWORD_INCORRECT;
		}
		String password_hash = encoder.encode(password);
		HashSet<String> roles = accountDto.getRoles();
		ArrayList<String> passwordHashes = new ArrayList<>();
		Account account = new Account(username, password_hash, passwordHashes, LocalDate.now(), false, roles);
		accountsRepository.insert(account);
		return OK;
	}

	@Override
	public boolean removeAccount(String id) {
		if (!accountsRepository.existsById(id)) {
			System.out.println("Account is not found");
			return false;
		}
		accountsRepository.deleteById(id);
		return true;
	}

	@Override
	public boolean addRole(String username, String role) {
		if (!accountsRepository.existsById(username)) {
			System.out.println("Account is not found");
			return false;
		}
		Account account = accountsRepository.findById(username).get();
		HashSet<String> roles = account.getRoles();
		roles.add(role);
		account.setRoles(roles);
		accountsRepository.save(account);
		return true;
	}

	@Override
	public boolean removeRole(String username, String role) {
		if (!accountsRepository.existsById(username)) {
			System.out.println("Account is not found");
			return false;
		}
		Account account = accountsRepository.findById(username).get();
		HashSet<String> roles = account.getRoles();
		roles.remove(role);
		account.setRoles(roles);
		accountsRepository.save(account);
		return true;
	}

	@Override
	public boolean updatePassword(String username, String password) {
		if (!accountsRepository.existsById(username)) {
			System.out.println("Account is not found");
			return false;
		}
		String resultCheck = checkPasswordMatches(password);
		if (resultCheck.length()!=0) {
			System.out.println("Password incorrect.\n"+resultCheck);
			return false;
		}
		Account account = accountsRepository.findById(username).get();
		String lastPasswordHash = account.getPassword_hash();
		ArrayList<String> lastPasswords = account.getLast_password_hashes();
		if (checkNewPasswordNonEqualsOld(password, lastPasswordHash))
			return false;
		if (lastPasswords.size() > 0) {
			for (String pass : lastPasswords) {
				if (checkNewPasswordNonEqualsOld(pass, password))
					return false;
			}
		}
		if (lastPasswords.size() < N_LAST_PASSWORDS) {
			lastPasswords.add(lastPasswordHash);
		} else {
			lastPasswords.remove(0);
			lastPasswords.add(lastPasswordHash);
		}
		String newPasswordHash = encoder.encode(password);
		account.setPassword_hash(newPasswordHash);
		account.setLast_password_hashes(lastPasswords);
		accountsRepository.save(account);
		return true;

	}

	private boolean checkNewPasswordNonEqualsOld(String password, String lastPasswordHash) {
		return encoder.matches(password, lastPasswordHash);
	}

	@Override
	public boolean revokeAccount(String username) {
		if (!accountsRepository.existsById(username)) {
			System.out.println("Account is not found");
			return false;
		}
		Account account = accountsRepository.findById(username).get();
		account.setRevoked(true);
		accountsRepository.save(account);
		return true;
	}

	@Override
	public boolean activateAccount(String username) {
		if (!accountsRepository.existsById(username)) {
			System.out.println("Account is not found");
			return false;
		}
		Account account = accountsRepository.findById(username).get();
		account.setRevoked(false);
		account.setActivationDate(LocalDate.now());
		accountsRepository.save(account);
		return true;
	}

	public static String checkPasswordMatches(String password) {
		if(password.length()<LENGTH)
			return "too few symbols";
		return
	password.matches
	("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$")?"":"Wrong password structure";
	}

}
