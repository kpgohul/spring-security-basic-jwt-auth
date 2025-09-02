# 🌐 spring-security-basic-jwt-auth

This is a **Spring Boot** project that demonstrates how to implement **Basic Authentication** and **JWT (JSON Web Token) Authentication** using **Spring Security**.

The project uses:
- **Spring Security** for securing endpoints and handling authentication
- **JJWT Maven library** for generating and validating JWT tokens
- **Role-based access control** to restrict access to endpoints based on user roles (e.g., `USER`, `ADMIN`)

---

## ✅ Features

- Basic Authentication with Spring Security
- JWT generation after successful login
- JWT validation using a custom filter
- Role-based access to protected resources

---

## 🔐 Authentication Workflow

1. The user authenticates using Basic Auth (`username` and `password`)
2. If credentials are valid, a **JWT token** is generated and returned
3. The client uses the **JWT token** (with `Authorization: Bearer <token>`) to access secured endpoints
4. The token is validated via a custom JWT filter before granting access

---

## 🛠️ Technologies Used

- Java 17+
- Spring Boot
- Spring Security
- Maven
- JJWT (`io.jsonwebtoken`)

---

## 👨‍💻 Author

**Gohul K**
---

