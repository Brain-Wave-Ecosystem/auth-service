package models

type RefreshToken struct {
	UserID int64  `json:"user_id" db:"user_id"`
	Role   string `json:"role" db:"role"`
}

type ConfirmCode struct {
	UserID int64  `json:"user_id" db:"user_id"`
	Name   string `json:"name" db:"name"`
	Code   int    `json:"code" db:"code"`
}
