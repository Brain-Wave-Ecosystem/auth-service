package models

type ConfirmEmailMail struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Code  int    `json:"code"`
	Time  int    `json:"time"`
}

type SuccessConfirmEmailMail struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	LoginURL string `json:"login_url"`
}
