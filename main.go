package main

import (
	"fmt"
	"bufio"
	"log"
	"time"
	//"os"
	"bytes"
	//"strings"
	"net/http"
	"go.bug.st/serial.v1/enumerator"
	"go.bug.st/serial.v1"
	"github.com/gorilla/websocket"
	"github.com/pkg/browser"
	"encoding/json"
	//"encoding/base64"
	"encoding/hex"
	"crypto/rand"
	"crypto/sha1"
	"io/ioutil"
	"regexp"
	"github.com/dgrijalva/jwt-go"
)

var (
	strline string
	secretHashKey string
	//token string
	upgrader = websocket.Upgrader{
		ReadBufferSize: 1024,
		WriteBufferSize: 1024,
		CheckOrigin: checkOrigin,
	}
	port = ":8087"
	host = "http://localhost"
	client_host = "http://localhost"
	client_port = ":8080"
	ws_path = "/device"
)

func commonMiddleware(next http.Handler) http.Handler {
	fmt.Println("in commonMiddleware")
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    	w.Header().Set("Access-Control-Allow-Origin", "*")
    	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-Width, Content-Type, Accept, Authorization")
        w.Header().Set("Content-Type", "application/json; charset=UTF-8")
        if r.Method == "OPTIONS" {
        	w.Header().Set("Access-Control-Allow-Methods", "PUT, POST, GET")
        	w.WriteHeader(200)
        	return
        }
        next.ServeHTTP(w, r)
    })
}

func validEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}

func checkOrigin(r *http.Request) bool{ 
	return true 
}

func generateKey() (secret []byte, hash string) {
	secret = make([]byte, 64)
	rand.Read(secret)
	h := sha1.New()
	h.Write(secret)
	hash = hex.EncodeToString(h.Sum(nil))
	return secret, hash
}

func retrieveKey() (string, error) {
	if secretHashKey != "" {
		fmt.Printf("current hash -> %v", secretHashKey)
		return secretHashKey, nil
	}
	secret, err := ioutil.ReadFile("secret")
	fmt.Printf("retrieved key-> %v", secret)
	if err != nil {
		return "", err
	} 
	h := sha1.New()
	h.Write(secret)
	secretHashKey = hex.EncodeToString(h.Sum(nil))
	fmt.Printf("retrieved hash -> %v", secretHashKey)
	return secretHashKey, nil
}

func runChannel(conn *websocket.Conn, portChan chan string){
	for {
		measurement, ok := <- portChan
		if ok {
			fmt.Printf("Sending %v on chanel", measurement)
			err := conn.WriteJSON(measurement)
			if err != nil{
				fmt.Printf("Error writing to websocket %v\n", err)
			}
		} else {
			break
		}
	}
}


type Registration struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Register_url string `json:"register_url"` 
	Key string `json:"key"`
}

type ConnectForm struct {
	Port string `json:"port"`
	Token string `json:"token"`
}


func sendJsnMsg(w http.ResponseWriter, message string, code int){
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	messageMap := map[string]string {"message": message }
	bodyBytes, _ := json.Marshal(messageMap)
	w.WriteHeader(code)
	w.Write(bodyBytes)
}

func socketServer(){
	mux := http.NewServeMux()

	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request){
		//var port string
		//var token string
		//check for a valid key
		//get port name from request
		fmt.Println("connecting..")
		var portString = r.URL.Query().Get("port")
		var token = r.URL.Query().Get("token")
		if portString == "" || token == "" {
			fmt.Println("port / token missing ")
			sendJsnMsg(w, "port and token required", 422)
			return 
		}
		//if portName == "" {
		//	portName = "/dev/ttys013"
		//}
		/*
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			sendJsnMsg(w, "could not parse request", 500)
			return 
		}
		json.Unmarshal(body, &connectForm)
		*/
		//validate token
		if !validateToken(token){
			fmt.Println("Invalid Login")
			sendJsnMsg(w, "Invalid Login", 401)
			return 
		}

		mode := &serial.Mode{ BaudRate: 115200 }
		port, err := serial.Open(portString, mode)
		if err != nil {
			sendJsnMsg(w, err.Error(), 503)
			return
		} 

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			sendJsnMsg(w, err.Error(), 500)
			return 
		}

		//create a new channel 
		portChan := make(chan string)
		go runChannel(conn, portChan)
		
		//scan port
		//line := make([]byte, 100)
		lineReader := bufio.NewReader(port)
		for {
			line, _, err := lineReader.ReadLine()
			//_, err := port.Read(line)
			fmt.Printf("%v", line)
			if err != nil {
				close(portChan)
				fmt.Println("Port closed")
				break
			} 
			select {
				case portChan <- string(line):
					fmt.Printf("Sending %v from port", line)
				default:
					fmt.Printf("no recipients found for %v", line)
			}	
		}
		fmt.Println("Channel closed")
	})

	mux.Handle("/register", commonMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		var rego Registration
		fmt.Println("registering")

		if secretHashKey != "" {
			sendJsnMsg(w, "Already registered", 409)
			return 
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil{
			sendJsnMsg(w, "could not parse request", 500)
			return 
		}
		json.Unmarshal(body, &rego)
		
		fmt.Printf("%v", rego)
		if !validEmail(rego.Username) || rego.Username == "" || rego.Password == "" {
			sendJsnMsg(w, "Invalid username / password", 422)
			return 
		}
		if rego.Register_url == "" {
			sendJsnMsg(w, "register url is required", 422)
			return 
		}

		key, hashKey := generateKey()
		rego.Key = hashKey
		requestBody, _ := json.Marshal(rego)
		client := http.Client{Timeout: time.Duration(5 * time.Second)}
		request, err := http.NewRequest("POST", rego.Register_url, bytes.NewBuffer(requestBody))
		if err != nil {
			sendJsnMsg(w, err.Error(), 500)
			return 
		}
		request.Header.Set("Content-type", "application/json")
		fmt.Printf("%v", request)
		response, err := client.Do(request)
		
		if err != nil {
			sendJsnMsg(w, err.Error(), 503)
			return 
		} else {
			defer response.Body.Close()
		}	
		
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			sendJsnMsg(w, err.Error(), 503)
			return 
		}
		
		//json.UnMarshal(bodyBytes, result)
		if response.StatusCode == 201 {	//success don't return body, just status
			//store the session token
			//token = result["token"].(string)
			// store the key in a file
			if err := saveKey(key); err != nil {
				sendJsnMsg(w, err.Error(), 503)
				return 
			}
		}

		secretHashKey = hashKey
		fmt.Printf("stored secretHashKey -> %v", secretHashKey)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(response.StatusCode)
		w.Write(bodyBytes)

	}))) 

	mux.Handle("/ports", commonMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		ports, err := serial.GetPortsList()
		if err == nil {
			json.NewEncoder(w).Encode(ports)
		} else {
			error := map[string]error{ "error": err}
			json.NewEncoder(w).Encode(error)
		}
	})))

	log.Fatal(http.ListenAndServe(port, mux))
}

func ports() ([]string, error) {
	return serial.GetPortsList()
}

func detailedList(){  
	ports, err := enumerator.GetDetailedPortsList() 
	if err != nil { 
			log.Fatal(err) 
	} 
	if len(ports) == 0 { 
			fmt.Println("No serial ports found!") 
			return 
	} 
	for _, port := range ports { 
			fmt.Printf("Found port: %s\n", port.Name) 
			if port.IsUSB { 
					fmt.Printf("   USB ID     %s:%s\n", port.VID, port.PID) 
					fmt.Printf("   USB serial %s\n", port.SerialNumber) 
			} 
	} 
} 

func launchBrowser(){
	retries := 5
	opened := false
	location := client_host + client_port

	for i := retries; i > 0; i-- {
		time.Sleep(time.Second)
		resp, err := http.Get(location)
		if err != nil {
			fmt.Printf("%v\n", err)
			continue
		} 
		resp.Body.Close()
		//should be 404
		//if resp.StatusCode == http.StatusOK {
			error_open := browser.OpenURL(location)
			if error_open == nil{
				opened = true
				break
			}
		//}	
	}
	if !opened {
		fmt.Printf("Failed to open location %s\n", location)
	}	
}

func createToken(secret []byte) (string, error) {
	// jwt.SigningMethodHS256 is an instance of jwt.SigningMethodHMAC
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func saveKey(key []byte) error {
	fmt.Printf("%v", key)
	return ioutil.WriteFile("secret", key, 0644)
}

func validateToken(token string) bool {

	hashKey, err := retrieveKey()
	if err != nil {
		return false
	}

	fmt.Printf("hex Key from validateToken -> %v", hashKey)
	tkn, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(hashKey), nil
	})
	if !tkn.Valid {
		return false
	}
	if err != nil {
		return false
	}
	// jwt.SigningMethodHMAC is a type that implmements jwt.SigningMethod
	if _, ok := tkn.Method.(*jwt.SigningMethodHMAC); !ok {
        //return false
    }
	return true
}


func main(){
	retrieveKey()
	ports, _ := ports()
	fmt.Printf("%v\n", ports)
	go launchBrowser()
	socketServer()
	
}
