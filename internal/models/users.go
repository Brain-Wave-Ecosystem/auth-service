package models

import "time"

type User struct {
	ID          int        `json:"id"`
	Email       string     `json:"email"`
	AvatarURL   *string    `json:"avatarUrl,omitempty"`
	Username    string     `json:"username"`
	FullName    *string    `json:"fullName,omitempty"`
	Bio         *string    `json:"bio,omitempty"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	Role        string     `json:"role"`
	IsVerified  *bool      `json:"isVerified,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
}

type RegisterUserRequest struct {
	Email    string
	Username string
	Password string
}

type RegisterUserResponse struct {
	User         *User
	AccessToken  string
	RefreshToken string
}
