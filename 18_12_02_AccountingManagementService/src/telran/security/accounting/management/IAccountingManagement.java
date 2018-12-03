package telran.security.accounting.management;

import telran.security.dto.AccountDto;
import telran.security.dto.ResponseCode;

public interface IAccountingManagement {

	public ResponseCode addAccount(AccountDto account);
	public ResponseCode removeAccount(String id);
	public ResponseCode addRole(String username, String role);
	public ResponseCode removeRole(String username, String role);
	public ResponseCode updatePassword(String username, String password);
	public ResponseCode revokeAccount(String username);
	public ResponseCode activateAccount(String username);

}
