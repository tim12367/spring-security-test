package uk.lazycat.spring_security_test.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoController {

	private Logger logger = LoggerFactory.getLogger(getClass());

	private static final List<Todo> TODOS_LIST = List.of(new Todo("test123", "Learn AWS"),
			new Todo("test123", "Get AWS Certified"));

	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos() {
		return TODOS_LIST;
	}

	@GetMapping("/users/{username}/todos")
//	@PreAuthorize("hasRole('USER') and #username == authentication.name") // 檢核存取角色權限
//	@PostAuthorize("returnObject.username == 'test123'") // 檢核回覆資料合法性
	@RolesAllowed({ "ADMIN", "USER" })
//	@Secured({ "ROLE_ADMIN" })
	public Todo retrieveTodosForSpecificUser(@PathVariable String username, Authentication authentication) throws JsonProcessingException {
		logger.debug("test authentication: " + authentication);
		return TODOS_LIST.get(0);
	}

	@PostMapping("/users/{username}/todos")
	public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo, Authentication authentication) throws JsonProcessingException {
		logger.info("test authentication: " + authentication);
		logger.info("Create {} for {}", todo, username);
	}

	record Todo(String username, String description) {
	}

}
