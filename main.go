package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/paymentintent"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User структура для хранения данных пользователя
type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// StripeConfig структура для конфигурации Stripe
type StripeConfig struct {
	PublishableKey string `json:"publishableKey"`
}

// PaymentRequest структура для запроса создания платежа
type PaymentRequest struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

var client *mongo.Client

func init() {
	// Загрузка переменных окружения
	if err := godotenv.Load(); err != nil {
		log.Println("Файл .env не найден")
	}

	// Инициализация Stripe
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	// Инициализация MongoDB
	clientOptions := options.Client().ApplyURI(os.Getenv("MONGODB_URI"))
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
		// Разрешаем запросы только с доверенных источников
		allowedOrigins := map[string]bool{
			"https://your-frontend-domain.com": true,
			"http://localhost:3000":            true,
		}

		origin := r.Header.Get("Origin")
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

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
		respondError(w, http.StatusBadRequest, "Пароль должен содержать минимум 6 символов")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера")
		return
	}

	collection := client.Database("market_auth").Collection("users")

	var existingUser User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&existingUser)
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

	respondJSON(w, http.StatusCreated, map[string]string{
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

	// Не возвращаем пароль в ответе
	dbUser.Password = ""
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Вход выполнен",
		"user":    dbUser,
	})
}

func stripeConfigHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, StripeConfig{
		PublishableKey: os.Getenv("STRIPE_PUBLISHABLE_KEY"),
	})
}

func createPaymentIntentHandler(w http.ResponseWriter, r *http.Request) {
	var paymentReq PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&paymentReq); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат данных")
		return
	}

	if paymentReq.Amount <= 0 {
		respondError(w, http.StatusBadRequest, "Неверная сумма платежа")
		return
	}

	if paymentReq.Currency == "" {
		paymentReq.Currency = "rub"
	}

	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(paymentReq.Amount),
		Currency: stripe.String(paymentReq.Currency),
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		log.Printf("Ошибка Stripe: %v", err)
		respondError(w, http.StatusInternalServerError, "Ошибка при создании платежа")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"clientSecret": pi.ClientSecret,
	})
}

func init() {
	// Загрузка .env (добавьте обработку ошибок)
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	// Получаем URI из переменных окружения
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MONGODB_URI not set in .env file")
	}

	// Проверяем схему подключения
	if !strings.HasPrefix(mongoURI, "mongodb://") && !strings.HasPrefix(mongoURI, "mongodb+srv://") {
		log.Fatal("Invalid MongoDB URI scheme. Must start with 'mongodb://' or 'mongodb+srv://'")
	}

	// Подключение к MongoDB
	clientOptions := options.Client().ApplyURI(mongoURI)
	var err error
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Проверка подключения
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully connected to MongoDB")
}

func main() {
	// Инициализация роутера
	r := mux.NewRouter()
	r.Use(enableCORS)

	// API маршруты
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/stripe-config", stripeConfigHandler).Methods("GET")
	r.HandleFunc("/create-payment-intent", createPaymentIntentHandler).Methods("POST")

	// Раздача статических файлов
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("public")))

	// Настройка HTTPS
	certFile := os.Getenv("SSL_CERT_FILE")
	keyFile := os.Getenv("SSL_KEY_FILE")

	if certFile == "" || keyFile == "" {
		log.Fatal("SSL сертификаты не настроены")
	}

	// Запуск сервера
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	fmt.Printf("Сервер запущен на https://localhost:%s\n", port)
	log.Fatal(http.ListenAndServeTLS(
		":"+port,
		certFile,
		keyFile,
		r,
	))
}
