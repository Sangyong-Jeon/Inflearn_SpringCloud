FROM openjdk:11-ea-slim
VOLUME /tmp
COPY build/libs/apigateway-service-1.0.jar ApigatewayService.jar
ENTRYPOINT ["java","-jar","ApigatewayService.jar"]