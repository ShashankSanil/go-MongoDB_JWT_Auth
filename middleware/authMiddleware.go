package middleware

import (
	//"fmt"
	"github.com/gin-gonic/gin"
	helper "go-Mongodb/helpers"
	"go-Mongodb/models"
	"net/http"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			//c.JSON(http.StatusInternalServerError, gin.H{"error":fmt.Sprintf("No Authorization header provided !!!")})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "No Authorization header provided !!!", Data: map[string]interface{}{"_data": nil}})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			//	c.JSON(http.StatusInternalServerError, gin.H{"error":err})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: err, Data: map[string]interface{}{"_data": nil}})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("userName", claims.Username)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.User_type)
		c.Next()
	}
}
