# Aşama 1: Build (Derleme)
FROM maven:3.9.6-eclipse-temurin-17-alpine AS build
WORKDIR /app
COPY pom.xml .
# Bağımlılıkları indirerek build aşamasını hızlandırıyoruz
RUN mvn dependency:go-offline -B
COPY src ./src
# Projeyi derle (Testleri atla)
RUN mvn clean package -DskipTests

# Aşama 2: Run (Çalıştırma)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/sgb-api-bridge-spring-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
