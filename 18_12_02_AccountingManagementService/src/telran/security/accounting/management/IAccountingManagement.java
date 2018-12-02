package telran.security.accounting.management;

import telran.security.dto.AccountDto;
import telran.security.dto.ResponseCode;

public interface IAccountingManagement {

	public ResponseCode addAccount(AccountDto account);
	public boolean removeAccount(String id);
	public boolean addRole(String username, String role);
	public boolean removeRole(String username, String role);
	public boolean updatePassword(String username, String password);
	public boolean revokeAccount(String username);
	public boolean activateAccount(String username);

}
