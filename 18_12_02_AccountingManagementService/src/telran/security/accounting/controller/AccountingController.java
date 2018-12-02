package telran.security.accounting.controller;

import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import telran.security.accounting.management.IAccountingManagement;
import telran.security.dto.AccountDto;
import telran.security.dto.ResponseCode;

import static telran.security.dto.AccountingApiConstants.*;

@RestController
public class AccountingController {
	@Autowired
	IAccountingManagement accounts;

	@PostMapping(ADD_ACCOUNT)
	ResponseCode addAccount(@RequestBody AccountDto accountDto) {
		return accounts.addAccount(accountDto);
	}

	@DeleteMapping(REMOVE_ACCOUNT)
	boolean removeAccount(@RequestParam(USERNAME) String id) {
		return accounts.removeAccount(id);
	}

	@PostMapping(UPDATE_PASSWORD)
	boolean updatePassword(@RequestBody HashMap<String, String> data) {
		return accounts.updatePassword(data.get("username"), data.get("password"));
	}

	@PostMapping(ADD_ROLE)
	boolean addRole(@RequestBody HashMap<String, String> data) {
		return accounts.addRole(data.get("username"), data.get("role"));
	}

	@DeleteMapping(REMOVE_ROLE)
	boolean removeRole
	(@RequestParam(USERNAME)String username,
			@RequestParam(ROLE_PARAM) String role){
		return accounts.removeRole(username, role);
	}

	@PostMapping(REVOKE_ACCOUNT)
	boolean revokeAccount(@RequestBody String username) {
		return accounts.revokeAccount(username);
	}

	@PostMapping(ACTIVATE_ACCOUNT)
	boolean activateAccount(@RequestBody String username) {
		return accounts.activateAccount(username);
	}

}
