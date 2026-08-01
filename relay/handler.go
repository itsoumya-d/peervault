// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

type Client struct {
	conn        *websocket.Conn
	roomManager *RoomManager
	roomID      string
	isSender    bool
}

func serveWs(roomManager *RoomManager, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	client := &Client{
		conn:        conn,
		roomManager: roomManager,
	}

	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.conn.Close()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}

		var msg SignalingMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("error unmarshaling message: %v", err)
			continue
		}

		c.handleMessage(msg)
	}
}

func (c *Client) handleMessage(msg SignalingMessage) {
	switch msg.Type {
	case "create_room":
		room := c.roomManager.CreateRoom(c)
		c.roomID = room.ID
		c.isSender = true
		c.sendJSON(SignalingMessage{
			Type:   "room_created",
			RoomID: room.ID,
		})
	case "join_room":
		success := c.roomManager.JoinRoom(msg.RoomID, c)
		if success {
			c.roomID = msg.RoomID
			c.isSender = false
			room := c.roomManager.GetRoom(msg.RoomID)
			if room != nil && room.Sender != nil {
				room.Sender.sendJSON(SignalingMessage{
					Type: "peer_joined",
				})
			}
		} else {
			c.sendJSON(SignalingMessage{
				Type: "error",
				Payload: map[string]interface{}{
					"message": "Room not found or full",
				},
			})
		}
	case "signal":
		room := c.roomManager.GetRoom(c.roomID)
		if room != nil {
			var target *Client
			if c.isSender {
				target = room.Receiver
			} else {
				target = room.Sender
			}
			if target != nil {
				target.sendJSON(SignalingMessage{
					Type:    "signal",
					Payload: msg.Payload,
				})
			}
		}
	}
}

func (c *Client) sendJSON(msg SignalingMessage) {
	err := c.conn.WriteJSON(msg)
	if err != nil {
		log.Printf("error writing message: %v", err)
	}
}
