FROM openjdk:11-ea-slim
VOLUME /tmp
COPY target/discoveryservice-1.0.jar DiscoveryService.jar
ENTRYPOINT ["java","-jar","DiscoveryService.jar"]