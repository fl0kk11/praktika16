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
    Name     string `json:"name"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

var client *mongo.Client

func init() {
    clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
    var err error
    client, err = mongo.Connect(context.TODO(), clientOptions)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("MongoDB подключена")
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, message string) {
    respondJSON(w, status, map[string]string{"error": message})
}

func enableCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Разрешаем запросы с любого источника
        w.Header().Set("Access-Control-Allow-Origin", "*")

        // Разрешаем определённые методы
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

        // Разрешаем определённые заголовки
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Если это OPTIONS-запрос — возвращаем только заголовки
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        // Иначе продолжаем обработку
        next.ServeHTTP(w, r)
    })
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

    var existingUser User
    err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
    if err == nil {
        respondError(w, http.StatusBadRequest, "Email уже используется")
        return
    }

    _, err = collection.InsertOne(context.TODO(), bson.M{
        "name":     user.Name,
        "email":    user.Email,
        "password": string(hashedPassword),
    })

    if err != nil {
        respondError(w, http.StatusInternalServerError, "Ошибка сервера")
        return
    }

    respondJSON(w, http.StatusOK, map[string]string{
        "message": "Регистрация успешна!",
    })
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        respondError(w, http.StatusBadRequest, "Неверный формат данных")
        return
    }

    collection := client.Database("market_auth").Collection("users")

    var dbUser User
    err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&dbUser)
    if err != nil {
        respondError(w, http.StatusUnauthorized, "Неверные данные")
        return
    }

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

    // Применяем CORS ко всем маршрутам
    r.Use(enableCORS)

   // API маршруты
r.HandleFunc("/register", registerHandler).Methods("POST")
r.HandleFunc("/login", loginHandler).Methods("POST")

// Раздаём статические файлы
r.PathPrefix("/").Handler(http.FileServer(http.Dir("public")))


    fmt.Println("Сервер запущен на http://localhost:8081")
    log.Fatal(http.ListenAndServe(":8081", r))
}