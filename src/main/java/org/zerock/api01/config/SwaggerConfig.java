package org.zerock.api01.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;

@Configuration
public class SwaggerConfig {
//  @Bean
//  public Docket api(){
//    return new Docket(DocumentationType.OAS_30)
//            .useDefaultResponseMessages(fales)
//            .select()
//            .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
//            .path(PathSelectors.any())
//            .build()
//            .apiInfo(apiInfo());
//  }
//  private ApiInfo apiInfo(){
//    return new ApiInfoBuilder()
//            .title("Boot API 01 Project Swagger")
//            .build();
//  }

  @Bean
  public OpenAPI openAPI() {
    return new OpenAPI()
            .info(new Info()
                    .title("Boot API 01 Project Swagger")
                    .version("1.0.0"));
  }

}