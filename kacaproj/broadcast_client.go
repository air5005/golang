package main

import (
	"fmt"
	"time"

	"github.com/scottkiss/kaca"
)

func main() {
	producer := kaca.NewClient(":8080", "ws")
	consumer := kaca.NewClient(":8080", "ws")
	c2 := kaca.NewClient(":8080", "ws")
	c2.ConsumeMessage(func(message string) {
		fmt.Println("c2 consume =>" + message)
	})
	consumer.Sub("say")
	consumer.Sub("you")
	consumer.ConsumeMessage(func(message string) {
		fmt.Println("consume =>" + message)
	})
	time.Sleep(time.Second * time.Duration(2))
	producer.Broadcast("broadcast...")
	time.Sleep(time.Second * time.Duration(2))
}
