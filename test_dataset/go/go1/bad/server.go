package main

import "fmt"

var DEBUG = true

func errorHandler(err error) {
    if err != nil {
        // Vulnerable: Exposing stack trace/error details
        fmt.Printf("Error occurred: %v\n", err)
        panic(err) // Often triggers stack trace printing
    }
}
