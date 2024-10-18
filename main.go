package main

import (
	"fmt"
)

func main() {

	server := NewAPIServer(":3000")
	server.run()
	fmt.Println("make run")
}
