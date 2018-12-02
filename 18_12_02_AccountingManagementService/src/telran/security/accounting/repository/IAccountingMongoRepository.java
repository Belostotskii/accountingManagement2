package telran.security.accounting.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import telran.security.accounting.Account;

@Repository
public interface IAccountingMongoRepository extends MongoRepository<Account, String> {
	
}
