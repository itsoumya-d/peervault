package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "4002"
	}

	roomManager := NewRoomManager()
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(roomManager, w, r)
	})

	log.Printf("Signaling Relay started on :%s", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
