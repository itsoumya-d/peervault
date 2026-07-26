package main

type SignalingMessage struct {
	Type    string      `json:"type"`
	RoomID  string      `json:"roomId,omitempty"`
	Payload interface{} `json:"payload,omitempty"`
}
