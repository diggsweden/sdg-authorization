package se.digg.sdg.samples.directaccessclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DirectApplication {

	/**
	 * Application that polls TestEvidenceService3 for information that is not bound to a specific user
	 * 
	 * @param args for the application
	 */
	
	public static void main(String[] args) {
		System.setProperty("java.net.preferIPv4Stack", "true");
		SpringApplication.run(DirectApplication.class, args);
	}
}
