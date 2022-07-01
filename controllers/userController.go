package controllers

import (
	"context"
	"go-Mongodb/database"
	helper "go-Mongodb/helpers"
	"go-Mongodb/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

//collection
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		//msg = fmt.Sprintf("Incorrect Password !!!")
		msg = "Incorrect Password !!!"
		check = false
	}
	return check, msg
}

//Sign-Up

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		defer cancel()

		if err := c.BindJSON(&user); err != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})

			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": validationErr.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: validationErr.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "error occured while checking for the email !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		if count > 0 {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Email already exists !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.Username, *user.User_type, user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "User not created !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "User not created !!", Data: map[string]interface{}{"_data": nil}})
			return
		}
		//c.JSON(http.StatusOK, gin.H{"_data": resultInsertionNumber, "_msg": "Registered Sucessfully..."})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusCreated, Message: "Registered Successfully..!!!", Data: map[string]interface{}{"_data": resultInsertionNumber}})
	}
}

//Login

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		defer cancel()

		if err := c.BindJSON(&user); err != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email is incorrect!!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Email is incorrect!!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if !passwordIsValid {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": msg})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: msg, Data: map[string]interface{}{"_data": nil}})
			return
		}

		if foundUser.Email == nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "User not Found !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "User not Found !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.Username, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}
		//c.JSON(http.StatusOK, gin.H{"_userData": foundUser, "_msg": "User logged In Successfully..."})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "User logged In Successfully...", Data: map[string]interface{}{"_data": foundUser}})
	}
}

//GetUsers

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		log.Println(startIndex)
		startIndex, _ = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}}}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage})
		defer cancel()
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while listing user items !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "error occured while listing user items !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}
		allUser := make([]bson.M, 0)

		if err = result.All(ctx, &allUser); err != nil {
			log.Fatal(err)
			return
		}
		if err = result.Close(ctx); err != nil {
			log.Fatal(err)
			return
		}
		//c.JSON(http.StatusOK, gin.H{"_msg": "All data fetched Successfully..!", "_data": allUser})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "All data fetched Successfully..!", Data: map[string]interface{}{"_data": allUser}})
	}
}

//GetUser

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}
		//c.JSON(http.StatusOK, gin.H{"_msg": "Getting User Detailes Suceesfully..!!!", "_data": user})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "Getting User Detailes Suceesfully..!!!", Data: map[string]interface{}{"_data": user}})
	}
}

//Get All Users

func GetAllUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "_users", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", 0, "$total_count"}}}},
			}}}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage})

		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while listing user items !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "error occured while listing user items !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}
		// result, err := userCollection.Find(ctx, bson.D{{}})
		// defer cancel()
		allUser := make([]bson.M, 0)

		if err = result.All(ctx, &allUser); err != nil {
			log.Fatal(err)
		}
		//c.JSON(http.StatusOK, gin.H{"_msg": "All data fetched Successfully..!", "_data": allUser})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "All data fetched Successfully..!", Data: map[string]interface{}{"_data": allUser}})
	}
}

//delete user

func DeleteUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		res, err := userCollection.DeleteOne(ctx, bson.M{"user_id": userId})
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		if res.DeletedCount < 1 {
			//c.JSON(http.StatusNotFound, gin.H{"_msg": "User with specified ID not found !!!"})
			c.JSON(http.StatusNotFound, models.UserResponse{Status: http.StatusNotFound, Message: "User with specified ID not found !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		//c.JSON(http.StatusOK, gin.H{"_msg": "User successfully deleted..!!!"})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "User successfully deleted..!!!", Data: map[string]interface{}{"_data": nil}})
	}
}

// update user

func EditUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		userId := c.Param("user_id")
		var updateduser models.User
		defer cancel()
		objId, _ := primitive.ObjectIDFromHex(userId)

		if err := c.BindJSON(&updateduser); err != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		validationErr := validate.Struct(updateduser)
		if validationErr != nil {
			//c.JSON(http.StatusBadRequest, gin.H{"_msg": validationErr.Error()})
			c.JSON(http.StatusBadRequest, models.UserResponse{Status: http.StatusBadRequest, Message: validationErr.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: err.Error(), Data: map[string]interface{}{"_data": nil}})
			return
		}

		if *user.Email == *updateduser.Email {
			count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
			//fmt.Println("count:", count)
			defer cancel()
			if err != nil {
				log.Panic(err)
				//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
				c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "error occured while checking for the email !!!", Data: map[string]interface{}{"_data": nil}})
				return
			}

			if count > 1 {
				//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
				c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Email already exists !!!", Data: map[string]interface{}{"_data": nil}})
				return
			}
		} else {
			count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
			defer cancel()
			if err != nil {
				log.Panic(err)
				//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
				c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "error occured while checking for the email !!!", Data: map[string]interface{}{"_data": nil}})
				return
			}

			if count > 0 {
				//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
				c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Email already exists !!!", Data: map[string]interface{}{"_data": nil}})
				return
			}
		}

		password := HashPassword(*updateduser.Password)
		updateduser.Password = &password

		updateduser.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		updateduser.User_id = userId

		token, refreshToken, _ := helper.GenerateAllTokens(*updateduser.Email, *updateduser.Username, *updateduser.User_type, userId)
		updateduser.Token = &token
		updateduser.Refresh_token = &refreshToken

		result, insertErr := userCollection.UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": bson.M{"username": *updateduser.Username, "email": *updateduser.Email, "password": updateduser.Password, "user_type": *updateduser.User_type, "token": updateduser.Token, "refresh_token": updateduser.Refresh_token, "updated_at": updateduser.Updated_at}})
		if insertErr != nil {
			//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Updation Failed !!!"})
			c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Updation Failed !!!", Data: map[string]interface{}{"_data": nil}})
			return
		}

		var newUser models.User
		if result.MatchedCount == 1 {
			err := userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&newUser)
			if err != nil {
				//c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Updation Failed !!!"})
				c.JSON(http.StatusInternalServerError, models.UserResponse{Status: http.StatusInternalServerError, Message: "Updation Failed !!!", Data: map[string]interface{}{"_data": nil}})
				return
			}
		}

		//c.JSON(http.StatusOK, gin.H{"_data": newUser, "_msg": "Upadted Sucessfully..."})
		c.JSON(http.StatusOK, models.UserResponse{Status: http.StatusOK, Message: "Upadted Sucessfully...", Data: map[string]interface{}{"_data": newUser}})
	}
}
