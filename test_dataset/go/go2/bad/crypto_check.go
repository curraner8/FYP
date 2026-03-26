package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	// B7: MD5 is broken for security purposes
	h := md5.New()
	h.Write([]byte("password123"))
	fmt.Printf("%x", h.Sum(nil))
}
