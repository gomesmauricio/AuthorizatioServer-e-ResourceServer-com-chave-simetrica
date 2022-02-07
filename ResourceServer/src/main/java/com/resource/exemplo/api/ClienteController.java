package com.resource.exemplo.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/clientes")
public class ClienteController {
	
	@GetMapping
	public ResponseEntity<String> getCliente() {
		return ResponseEntity.ok("Recurso getClientes Test!") ;
	}

}
