// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Room struct {
	ID        string
	Sender    *Client
	Receiver  *Client
	CreatedAt time.Time
}

type RoomManager struct {
	Rooms map[string]*Room
	mu    sync.RWMutex
}

func NewRoomManager() *RoomManager {
	rm := &RoomManager{
		Rooms: make(map[string]*Room),
	}
	go rm.cleanupRoutine()
	return rm
}

func (rm *RoomManager) CreateRoom(sender *Client) *Room {
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)

	room := &Room{
		ID:        id,
		Sender:    sender,
		CreatedAt: time.Now(),
	}

	rm.mu.Lock()
	rm.Rooms[id] = room
	rm.mu.Unlock()

	return room
}

func (rm *RoomManager) GetRoom(id string) *Room {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.Rooms[id]
}

func (rm *RoomManager) JoinRoom(id string, receiver *Client) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	room, ok := rm.Rooms[id]
	if !ok {
		return false
	}

	if room.Receiver != nil {
		return false
	}

	room.Receiver = receiver
	return true
}

func (rm *RoomManager) cleanupRoutine() {
	ticker := time.NewTicker(time.Hour)
	for range ticker.C {
		rm.cleanup()
	}
}

func (rm *RoomManager) cleanup() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	for id, room := range rm.Rooms {
		if now.Sub(room.CreatedAt) > 24*time.Hour {
			delete(rm.Rooms, id)
		}
	}
}
