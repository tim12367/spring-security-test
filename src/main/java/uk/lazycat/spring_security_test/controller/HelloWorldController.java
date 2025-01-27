package uk.lazycat.spring_security_test.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
	@GetMapping("/hello-world")
	public String helloWorld() {
		return "Hello World";
	}
}
