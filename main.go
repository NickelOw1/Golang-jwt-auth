package main

import (
	"encoding/json"
	"log"
	"net/http"
	"github.com/joho/godotenv"
	"github.com/gorilla/mux"
	"os"
	"github.com/dgrijalva/jwt-go"
	"time"
	"context"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TokenData struct {
	RefreshToken	string  `json:"refreshToken"`
	AccessToken	string  `json:"accessToken"`
}

type SearchResult struct {
	ID		primitive.ObjectID `bson:"_id,omitempty"`
	Guid		string `bson:"guid"`
	RefreshToken	string `bson:"refreshToken"`
}

func verifyRefreshToken(refreshToken string) (string, bool) {

	claims := jwt.MapClaims{}
	token, _ := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
    	return []byte(os.Getenv("REFRESH_KEY")), nil
	})
	isValid := token.Valid
	guid := claims["guid"].(string)
	return guid, isValid
}

func updateTokenInDB(refreshTokenString string, guid string) (TokenData, *http.Cookie) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, _ := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	collection := client.Database(os.Getenv("MONGO_DB")).Collection(os.Getenv("MONGO_COLLECTION"))

	var tokenFromDB SearchResult
	filter := bson.D{{"guid", guid}}
	collection.FindOne(ctx, filter).Decode(&tokenFromDB)

	err := bcrypt.CompareHashAndPassword([]byte(tokenFromDB.RefreshToken), []byte(refreshTokenString))
	if err != nil {
		panic(err)
	}

	tokenData, newTokenCookie := generateNewTokens(guid)

	hashedRT,_ := bcrypt.GenerateFromPassword([]byte(tokenData.RefreshToken), bcrypt.DefaultCost)
	collection.UpdateByID(ctx, tokenFromDB.ID, bson.D{{"$set", bson.M{"refreshToken": string(hashedRT)}}}) 

	return tokenData, newTokenCookie
}

func saveTokensToDB(refreshTokenString string, guid string) {
	hashedRT,_ := bcrypt.GenerateFromPassword([]byte(refreshTokenString), bcrypt.DefaultCost)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, _ := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_URI")))
	collection := client.Database(os.Getenv("MONGO_DB")).Collection(os.Getenv("MONGO_COLLECTION"))
	collection.InsertOne(ctx, bson.D{{"guid", guid}, {"refreshToken", string(hashedRT)}})
}

func generateNewTokens(guid string) (TokenData, *http.Cookie) {
	accessKey := os.Getenv("ACCESS_KEY")
	accessSigningKey := []byte(accessKey)
	accessToken := jwt.New(jwt.SigningMethodHS512)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["guid"] = guid
	accessClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	accessTokenString, _ := accessToken.SignedString(accessSigningKey)

	refreshKey := os.Getenv("REFRESH_KEY")
	refreshSigningKey := []byte(refreshKey)
	refreshToken := jwt.New(jwt.SigningMethodHS512)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["guid"] = guid
	refreshClaims["exp"] = time.Now().Add(time.Hour * 24 * 60).Unix()
	refreshTokenString, _ := refreshToken.SignedString(refreshSigningKey)

	tokenData := TokenData{RefreshToken: refreshTokenString, AccessToken: accessTokenString}

	tokenCookie := &http.Cookie{
		Name:   "refreshToken",
		Value:  refreshTokenString,
		MaxAge: 60 * 60 * 24 * 60,
		HttpOnly: true,
    }

	return tokenData, tokenCookie
}

func getJwtTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	query := r.URL.Query()
	guid := query.Get("guid")

	tokenData, tokenCookie := generateNewTokens(guid)
	saveTokensToDB(tokenData.RefreshToken, guid)

	http.SetCookie(w, tokenCookie)
	json.NewEncoder(w).Encode(tokenData)
}

func refreshJwtTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	cookieToken, _ := r.Cookie("refreshToken")
	guid, isValid := verifyRefreshToken(cookieToken.Value)

	if isValid == true {
		tokenData, newTokenCookie := updateTokenInDB(cookieToken.Value, guid)

		http.SetCookie(w, newTokenCookie)
		json.NewEncoder(w).Encode(tokenData)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
	  log.Fatal("Error loading .env file")
	}
  
	r := mux.NewRouter()

	r.HandleFunc("/gettokens", getJwtTokens).Methods("POST")
	r.HandleFunc("/refreshtokens", refreshJwtTokens).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}