package kopo.poly;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories
@SpringBootApplication
public class SpringJwtJdk17Application {

    public static void main(String[] args) {
        SpringApplication.run(SpringJwtJdk17Application.class, args);
    }

}
