package org.zerock.api01.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
//
//  private ApiInfo apiInfo(){
//    return new ApiInfoBuilder()
//            .title("Boot API 01 Project Swagger")
//            .build();
//  }

  @Bean
  public OpenAPI openAPI() {
    SecurityScheme securityScheme = new SecurityScheme()
            .type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")
            .in(SecurityScheme.In.HEADER).name("Authorization");
    SecurityRequirement securityRequirement = new SecurityRequirement().addList("bearerAuth");
    return new OpenAPI()
            .components(new Components().addSecuritySchemes("bearerAuth", securityScheme))
            .info(new Info()
                    .title("Boot API 01 Project Swagger")
                    .version("1.0.0"));
  }

//  private ApiKey apiKey() {
//    return new ApiKey("Authorization", "Bearer Token", "header");
//  }
//
//  private SecurityContext securityContext() {
//    return SecurityContext.builder().securityReferences(defaultAuth())
//            .operationSelector(selector -> selector.requestMappingPattern().startsWith("/api/")).build();
//  }

}