package main

import (
	"fmt"
	"log"
	"net/http"
)

func sayhelloName(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Println("path:", r.URL.Path)
	fmt.Println("Method:", r.Method)
	fmt.Println("Host:", r.URL.Host)
	fmt.Println("RawPath:", r.URL.RawPath)
	fmt.Fprintf(w, "hello go")
	//http.NotFound(w, r)
}

func main() {
	http.HandleFunc("/", sayhelloName)
	err := http.ListenAndServe("127.0.0.1:9090", nil)
	if err != nil {
		log.Fatal("ListenAndServer: ", err)
	}
}
