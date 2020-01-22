package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
	"bytes"
	"strings"
	"fmt"
	"strconv"
	"math/rand"
	
	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

const difficulty = 4


type DNSServer struct {
	IpAddr string
	PublicKey string
}

type DNSTx struct {
	Hostname string
	IpAddr string
}

type DNSListAddition struct {
	IpAddr string
	PublicKey string
}

type Block struct {
	Index     int
	Timestamp string
	Hostname  string
	IpAddr	  string
	Hash      string
	PrevHash  string
	Difficulty int
	Nonce 	   float64
}

var Blockchain []Block
var DNSServerList []DNSServer
var DNSTxList []DNSTx

func hashing_routine(id int, block Block ,results chan<- string) {
	fmt.Println("Hasher", id, "is hashing now") 
	record := string(block.Index) + block.Timestamp + block.Hostname + block.IpAddr + block.PrevHash + strconv.Itoa(block.Difficulty)
	h := sha256.New()
	for {
		nonce := rand.Float64()
		str_nonce := fmt.Sprint("%f",nonce)
		h.Write([]byte(record + str_nonce))
		hashed := h.Sum(nil)
		if isHashValid(hex.EncodeToString(hashed),difficulty) {
			fmt.Println("Hasher [", id, "] won!")
			results<- hex.EncodeToString(hashed)
			break
		} else {
			fmt.Println("[!]Hasher[",id,"] failed. Produced:[",hex.EncodeToString(hashed),"]")
		}
	}
}


func calculateHash(block Block) string {
	str_nonce := fmt.Sprintf("%x", block.Nonce)
	record := string(block.Index) + block.Timestamp + block.Hostname + block.IpAddr + block.PrevHash + strconv.Itoa(block.Difficulty) + str_nonce
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}



func generateBlock(oldBlock Block, Hostname, IpAddr string) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Hostname = Hostname
	newBlock.IpAddr = IpAddr 
	
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Difficulty = difficulty

	for {
		newBlock.Nonce = rand.Float64()
		if !isHashValid(calculateHash(newBlock), newBlock.Difficulty) {
			fmt.Println(calculateHash(newBlock), "Do more Work!")
			continue
		} else {
			fmt.Println(calculateHash(newBlock), "work Done!")
			newBlock.Hash = calculateHash(newBlock)
			break
		}
	}

	return newBlock, nil
}

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

func replaceChain(newBlocks []Block) {
	if len(newBlocks) > len(Blockchain) {
		Blockchain = newBlocks
	}
}

func checkDNSEntry(Server DNSServer) bool {
	for _, server := range DNSServerList {
		if Server.IpAddr == server.IpAddr {
			return false
		}
	}
	return true
}

func addDNSList(newDNSEntries []DNSServer) {
	for _,entry := range newDNSEntries {
		if checkDNSEntry(entry) {
			DNSServerList = append(DNSServerList, entry)
		}
	}
}

func AddDns(IpAddr, PublicKey string) (DNSServer, error) {
	var newDNS DNSServer

	newDNS.IpAddr = IpAddr
	newDNS.PublicKey = PublicKey
	return newDNS, nil 
}


func run() error {
	mux := makeMuxRouter()
	httpAddr := os.Getenv("ADDR")
	log.Println(httpAddr)
	log.Println("Listening on ", os.Getenv("ADDR"))
	s := &http.Server{
		Addr:           ":" + "8080",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}


func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}


func updateDNSList() {
	for _, servers := range DNSServerList {
		reqBody, err := json.MarshalIndent(DNSServerList, "","	")
		if err != nil {
			spew.Dump(err)
		}
		resp, err := http.Post("http://" + servers.IpAddr + ":8080" + "/CheckDNSServerList","application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			panic(err)
		}
		log.Println(resp)
	}
}



func handleBroadcast() {

	for _,servers := range DNSServerList {
			reqBody, err := json.MarshalIndent(Blockchain, "", "	")
			if err != nil {
				spew.Dump(err)
			}
			resp, err := http.Post("http://" + servers.IpAddr + ":8080" + "/CheckBlockLength","application/json", bytes.NewBuffer(reqBody))
			if err != nil {
				panic(err)
			}
		log.Println(resp)
	}
	updateDNSList()
}

func handleLength(w http.ResponseWriter, r *http.Request) {
	var newChain []Block
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&newChain); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
	}

	defer r.Body.Close()
	replaceChain(newChain)
	spew.Dump(Blockchain)
}


func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var m DNSTx

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m.Hostname, m.IpAddr)
	if err != nil {
		respondWithJSON(w, r, http.StatusInternalServerError, m)
		return
	}
	if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
		newBlockchain := append(Blockchain, newBlock)
		replaceChain(newBlockchain)
		spew.Dump(Blockchain)
	}

	handleBroadcast()
	respondWithJSON(w, r, http.StatusCreated, newBlock)
}

func handleDNSList(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(DNSServerList,"","	")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return 
	}
	io.WriteString(w, string(bytes))
}

func handleDNSListWrite(w http.ResponseWriter, r *http.Request) {
	var submission DNSListAddition 

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&submission); err != nil {
		respondWithJSON(w, r, http.StatusInternalServerError, submission)
	}

	defer r.Body.Close()

	newDNS, err := AddDns(submission.IpAddr, submission.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	DNSServerList = append(DNSServerList, newDNS)
	spew.Dump(DNSServerList)
	respondWithJSON(w, r, http.StatusCreated, newDNS)
}

func handleDNSUpdate(w http.ResponseWriter, r *http.Request) {
	var newList []DNSServer
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&newList); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
	}

	defer r.Body.Close()
	addDNSList(DNSServerList)
	spew.Dump(DNSServerList)
}


func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	muxRouter.HandleFunc("/DNSList", handleDNSList).Methods("GET")
	muxRouter.HandleFunc("/DNSList", handleDNSListWrite).Methods("POST")
	muxRouter.HandleFunc("/CheckBlockLength", handleLength).Methods("POST")
	muxRouter.HandleFunc("/CheckDNSServerList", handleDNSUpdate).Methods("POST")
	return muxRouter
}


func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		t := time.Now()
		genesisBlock := Block{0, t.String(), "www.insight.com", "1.1.1.1", "", "",difficulty,0}
		spew.Dump(genesisBlock)
		Blockchain = append(Blockchain, genesisBlock)

		selfServer := DNSServer{"127.0.0.1","Hello World"}
		DNSServerList = append(DNSServerList, selfServer)

	}()
	log.Fatal(run())

}
