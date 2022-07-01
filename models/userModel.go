package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type User struct {
	ID            primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username      *string            `json:"username" validate:"required,min=2,max=100"`
	Email         *string            `json:"email" validate:"email,required"`
	Password      *string            `json:"password" validate:"required,min=8"`
	User_id       string             `json:"user_id"`
	User_type     *string            `json:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	Token         *string            `json:"token"`
	Refresh_token *string            `json:"refresh_token"`
	Created_at    time.Time          `json:"created_at"`
	Updated_at    time.Time          `json:"updated_at"`
}

type UserResponse struct {
	Status  int                    `json:"status"`
	Message string                 `json:"_msg"`
	Data    map[string]interface{} `json:"data"`
}
