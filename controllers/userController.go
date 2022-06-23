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
			c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"_msg": validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
			return
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.Username, *user.User_type, user.User_id) //user.User_id is same as *&user.User_id
		user.Token = &token
		user.Refresh_token = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "User not created !!!"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"_insertedId": resultInsertionNumber, "_msg": "Registered Sucessfully..."})
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
			c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email is incorrect!!!"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "User not Found !!!"})
			return
		}

		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.Username, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"_userData": foundUser, "_msg": "User logged In Successfully..."})
	}
}

//GetUsers

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
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
		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}},
			{"data", bson.D{{"$push", "$$ROOT"}}}}}}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			}}}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while listing user items !!!"})
		}
		var allUser []bson.M

		if err = result.All(ctx, &allUser); err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, allUser[0])
	}
}

//GetUser

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}

//Get All Users

func GetAllUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"$sum", 1}}},
			{"data", bson.D{{"$push", "$$ROOT"}}}}}}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", 0, "$total_count"}}}},
			}}}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while listing user items !!!"})
		}

		// result, err := userCollection.Find(ctx, bson.D{})
		// defer cancel()
		var allUser []bson.M

		if err = result.All(ctx, &allUser); err != nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, allUser[0])

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
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			return
		}

		if res.DeletedCount < 1 {
			c.JSON(http.StatusNotFound, gin.H{"_msg": "User with specified ID not found !!!"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"_msg": "User successfully deleted..!!!"})
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
			c.JSON(http.StatusBadRequest, gin.H{"_msg": err.Error()})
			return
		}

		validationErr := validate.Struct(updateduser)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"_msg": validationErr.Error()})
			return
		}

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": err.Error()})
			return
		}

		if *user.Email == *updateduser.Email {
			count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
			defer cancel()
			if err != nil {
				log.Panic(err)
				c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
				return
			}

			if count > 1 {
				c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
				return
			}
		} else {
			count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
			defer cancel()
			if err != nil {
				log.Panic(err)
				c.JSON(http.StatusInternalServerError, gin.H{"_msg": "error occured while checking for the email !!!"})
				return
			}

			if count > 0 {
				c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Email already exists !!!"})
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
			c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Updation Failed !!!"})
			return
		}

		var newUser models.User
		if result.MatchedCount == 1 {
			err := userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&newUser)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"_msg": "Updation Failed !!!"})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{"_data": newUser, "_msg": "Upadted Sucessfully..."})
	}
}
