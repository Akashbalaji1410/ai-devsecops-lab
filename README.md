# DevSecOps Project

This project demonstrates an end-to-end DevSecOps CI/CD workflow using a Spring Boot application and a set of modern security and deployment tools. The goal is to automate build, testing, code quality checks, container scanning, image publishing, and Kubernetes deployment while enforcing security best practices throughout the pipeline.

## Overview

The application is a simple Spring Boot service packaged into a Docker image and deployed through Jenkins into a Kubernetes cluster. Each stage of the pipeline validates the code and image before deployment, helping catch issues early and reduce risk.

## Architecture

![Project Architecture](https://github.com/praveensirvi1212/DevSecOps-project/blob/main/Images/architecture.png)

## Tools Used

- Git
- GitHub
- Jenkins
- Maven
- JUnit
- SonarQube
- Docker
- Trivy
- AWS S3
- Docker Hub
- Kubernetes (Minikube / kubectl)
- HashiCorp Vault
- Slack

## Project Structure

```text
DevSecOps-Project/
├── Dockerfile
├── Jenkinsfile
├── pom.xml
├── mvnw
├── mvnw.cmd
├── README.md
├── spring-boot-deployment.yaml
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/example/demo/
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/
│           └── com/example/demo/
├── vars/
│   └── helloWorld.groovy
├── Images/
├── docker_installation.md
├── Jenkins_installation.md
├── kubernetes-cd.hpi
├── sonarqube_installation_with_postgres_database.md
└── target/
```

## Prerequisites

Before running or deploying this project, make sure you have:

1. Java 11+
2. Maven or the included Maven wrapper
3. Git
4. GitHub repository access
5. Jenkins installed and configured
6. SonarQube server running
7. Docker installed
8. Trivy installed
9. AWS account with S3 access
10. Docker Hub account
11. Kubernetes cluster or Minikube
12. kubectl configured
13. HashiCorp Vault configured for secrets
14. Slack webhook or notification integration

## CI/CD Pipeline Flow

1. Jenkins fetches the source code from GitHub.
2. Maven builds the application.
3. JUnit runs the unit tests.
4. SonarQube analyzes the source code and checks the quality gate.
5. Docker builds the application image.
6. Trivy scans the Docker image for vulnerabilities.
7. The image is pushed to Docker Hub.
8. Kubernetes deployment files are applied to the cluster.
9. Slack or other notifications send status updates after each stage.

## Local Development

### Run the Spring Boot application

```bash
./mvnw spring-boot:run
```

Then open:

```text
http://localhost:8080
```

### Run tests

```bash
./mvnw test
```

### Build the project

```bash
./mvnw clean package
```

## Docker Build

Build the Docker image locally:

```bash
docker build -t devsecops-demo:latest .
```

Run the container:

```bash
docker run -p 8080:8080 devsecops-demo:latest
```

## Deployment to Kubernetes

The project includes a Kubernetes deployment manifest:

- `spring-boot-deployment.yaml`

Apply it with:

```bash
kubectl apply -f spring-boot-deployment.yaml
```

## Jenkins Pipeline

The repository includes a `Jenkinsfile` that automates the DevSecOps flow. It handles the build, testing, static analysis, security scanning, containerization, and deployment stages.

## Security Focus

This project is built around the idea of shifting security left by checking code quality and vulnerabilities early in the development lifecycle. The pipeline helps ensure that:

- insecure code does not reach production,
- container images are scanned before release,
- deployment is automated and repeatable,
- credentials and sensitive values are managed through secret stores.

## Notes

This repository is primarily intended for learning and demonstration of a full DevSecOps integration pipeline. Depending on your environment, you may need to adjust credentials, endpoints, and cluster configuration.

## License

This project is provided for educational and demonstration purposes.
