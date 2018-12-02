package telran.security.accounting;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("account")
public class Account {
	public Account(String username, String password_hash, ArrayList<String> last_password_hashes, LocalDate activationDate,
			boolean revoked, HashSet<String> roles) {
		super();
		this.username = username;
		this.password_hash = password_hash;
		this.last_password_hashes = last_password_hashes;
		this.activationDate = activationDate;
		this.revoked = revoked;
		this.roles = roles;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword_hash() {
		return password_hash;
	}
	public void setPassword_hash(String password_hash) {
		this.password_hash = password_hash;
	}
	public ArrayList<String> getLast_password_hashes() {
		return last_password_hashes;
	}
	public void setLast_password_hashes(ArrayList<String> last_password_hashes) {
		this.last_password_hashes = last_password_hashes;
	}
	public LocalDate getActivationDate() {
		return activationDate;
	}
	public void setActivationDate(LocalDate activationDate) {
		this.activationDate = activationDate;
	}
	public boolean isRevoked() {
		return revoked;
	}
	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}
	public HashSet<String> getRoles() {
		return roles;
	}
	public void setRoles(HashSet<String> roles) {
		this.roles = roles;
	}
	@Id
	String username;
	String password_hash;
	ArrayList<String> last_password_hashes;
	LocalDate activationDate;
	boolean revoked;
	HashSet<String> roles;
}
