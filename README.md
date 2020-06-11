# thilux JWT

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/thilux/go-jwt/Go?logo=github&style=for-the-badge)](https://github.com/thilux/go-jwt/actions?query=workflow%3AGo)

This is a very simple implementation of a JWT encode/decode library in Go. I have mainly done this to play around with some Go concepts and standard library.

## Getting started

To install thilux's go-jwt:
        `go get xxxxxxxxx/thilux/jwt`

A very basic usage example:

```go
package main

import (
    "fmt"
    "thilux.io/thilux/jwt"
)

type myUserDetails struct {

    Username string `json:"username"`
    FirstName string `json:"firstName"`
    LastName string `json:"lastName"`
    Claims map[string]string `json:"claims"`
}

const tokenSecret = "19db940ghf439bf340fgu3bdlkwnhfpehdp"

func main() {

    claims := map[string]string{"admin": "no", "email":"myuser@email.com"}
    userDetails := myUserDetails{Username: "myuser", FirstName: "First", LastName: "Last", Claims: claims}

    token, err := jwt.Encode(userDetails, tokenSecret, "HS256")

    if err != nil {
        fmt.Println("Error generating token: " + err.Error())
        return
    }

    fmt.Println("Token: " + token)
}
```

## License

This project is under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full text.