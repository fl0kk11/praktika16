package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"

    "github.com/gorilla/mux"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "golang.org/x/crypto/bcrypt"
)

type User struct {
    ID       string `json:"id,omitempty"`
    Name     string `json:"name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
    respondJSON(w, status, map[string]string{"error": message})
}

var client *mongo.Client

func init() {
    // Подключение к MongoDB
    clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
    client, _ = mongo.Connect(context.TODO(), clientOptions)
    collection := client.Database("market_auth").Collection("users")

    fmt.Println("MongoDB подключена")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        respondError(w, http.StatusBadRequest, "Неверный формат данных")
        return
    }

    if len(user.Password) < 6 {
        respondError(w, http.StatusBadRequest, "Пароль слишком короткий")
        return
    }

    hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

    collection := client.Database("market_auth").Collection("users")

    // Проверяем, существует ли пользователь с таким email
    var existingUser User
    err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
    if err == nil { // Если пользователь найден
        respondError(w, http.StatusBadRequest, "Email уже используется")
        return
    }

    // Сохраняем нового пользователя
    result, _ := collection.InsertOne(context.TODO(), bson.M{
        "name":     user.Name,
        "email":    user.Email,
        "password": string(hashedPassword),
    })

    respondJSON(w, http.StatusOK, map[string]string{
        "message": "Регистрация успешна!",
        "user_id": result.InsertedID.(primitive.ObjectID).Hex(),
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        respondError(w, http.StatusBadRequest, "Неверный формат данных")
        return
    }

    collection := client.Database("market_auth").Collection("users")

    // Ищем пользователя по email
    var dbUser User
    err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&dbUser)
    if err != nil {
        respondError(w, http.StatusUnauthorized, "Неверные данные")
        return
    }

    // Сравниваем пароли
    if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
        respondError(w, http.StatusUnauthorized, "Неверные данные")
        return
    }

    respondJSON(w, http.StatusOK, map[string]interface{}{
        "message": "Вход выполнен",
        "user":    dbUser,
    })
}

func main() {
    r := mux.NewRouter()

    // Статические файлы
    r.PathPrefix("/").Handler(http.FileServer(http.Dir("public")))

    // API маршруты
    r.HandleFunc("/register", registerHandler).Methods("POST")
    r.HandleFunc("/login", loginHandler).Methods("POST")

    fmt.Println("Сервер запущен на http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}