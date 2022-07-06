# spring-boot-3-jwt

## Endpoints

| **HTTP** | **Endpoint** | **Info**                             |
|:--------:|:------------:|--------------------------------------|
| GET      | /up          | Not Secured                          |
| GET      | /secured     | Needs JWT Token Authorization Header |
| POST     | /login       | Retrieves JWT Token                  |


### Authentication params (request body) /login
```json
{
  "username": "admin",
  "password": "admin"
}
```

