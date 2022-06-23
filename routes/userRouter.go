package routes

import(
	controller "go-Mongodb/controllers"
	"go-Mongodb/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
	incomingRoutes.GET("/userslist", controller.GetAllUsers())
	incomingRoutes.DELETE("/users/:user_id", controller.DeleteUser())
	incomingRoutes.PUT("/users/:user_id", controller.EditUser())
}