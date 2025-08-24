package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents the data stored for a single user session.
type Session struct {
	ID        string    // Unique identifier for the session (e.g., UUID)
	UserID    uuid.UUID // ID of the user associated with this session
	ExpiresAt time.Time // When the session becomes invalid
	CreatedAt time.Time // When the session was created
	IpAddress *string   // Optional ip address
	UserAgent *string   // Optional UserAgent
}
