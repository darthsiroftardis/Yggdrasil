package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/elliptic"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"bytes"
	"strings"
	"fmt"
	"strconv"
	rand "math/rand"
	"math/big"
	"encoding/asn1"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

const difficulty = 4

type Transaction struct {
	Number		string
	Input		inputList
	Output		outputList
	Signature 	string
}

type Transactions []Transaction


type TransactionOutput struct {
	PublicKey 	string
	Hostname	string
	IpAddr	string
}

type outputList []TransactionOutput

func (outputs outputList) OutputString() string {
	var outputString string
	for _,output := range outputs {
		outputString += output.PublicKey
		outputString += output.Hostname
		outputString += output.IpAddr
	}
	return outputString
}

type TransactionInput struct {
	Number	string
	Outputs outputList
}

type inputList []TransactionInput

func (inputs inputList) InputString() string {
	var inputString string
	for _,input := range inputs {
		inputString += input.Number
		inputString += input.Outputs.OutputString()
	}

	return inputString	
}

type Wallet struct {
	privateKey 		*ecdsa.PrivateKey
	publicKeyBytes  []byte
}

type ECDSASignature struct {
	R, S *big.Int
}

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
	Index      int
	Timestamp  string
	Tx		   Transaction
	Hash       string
	PrevHash   string
	Difficulty int
	Nonce 	   float64
}

var Blockchain []Block
var DNSServerList []DNSServer
var DNSTxList []DNSTx

func (tx Transaction) RetrievePublicKey() *ecdsa.PublicKey {
	keyString := tx.Input[0].Outputs[0].PublicKey
	keyBytes, err := hex.DecodeString(keyString)
	if err != nil {
		panic(err)
	}
	x,y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
	var VerifyKey = &ecdsa.PublicKey{
		elliptic.P256(), x, y,
	}
	return VerifyKey
}

func (w Wallet) GetPublicString() string {
	publicKeyString := hex.EncodeToString(w.publicKeyBytes)
	return publicKeyString
}

func CreateWallet() (Wallet,error) {
	var w Wallet	
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return Wallet{},err
	}
	w.privateKey = priv
	w.publicKeyBytes = elliptic.Marshal(priv.PublicKey, priv.PublicKey.X, priv.PublicKey.Y)
	//fmt.Println(w.publicKeyBytes)
	return w,nil
}

func (tx Transaction) ValidateTransaction() (bool) {
	signatureString := tx.Signature
	signatureBytes,err := hex.DecodeString(signatureString)
	if err != nil {
		panic(err)
	}
	signature := ECDSASignature{}
	_,err = asn1.Unmarshal(signatureBytes, &signature)

	hash, err := hex.DecodeString(tx.Number)

	verificationKey := tx.RetrievePublicKey()
	valid := ecdsa.Verify(verificationKey, hash[:], signature.R, signature.S)
	return valid
}


func (tx Transaction) TransactionString() string {
	var txString string
	txString += tx.Number
	txString += tx.Input.InputString()
	txString += tx.Output.OutputString()
	txString += tx.Signature 
	return txString
}

/*
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
*/

func calculateHash(block Block) string {
	str_nonce := fmt.Sprintf("%x", block.Nonce)
	record := string(block.Index) + block.Timestamp + block.Tx.TransactionString() + block.PrevHash + strconv.Itoa(block.Difficulty) + str_nonce
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}



func generateBlock(oldBlock Block, tx Transaction) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Tx = tx
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
	var m Transaction


	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	if _,err := asn1.Unmarshal(bodyBytes, &m); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	if m.ValidateTransaction() != true {
		return
	}

	newBlock, err := generateBlock(Blockchain[len(Blockchain)-1], m)
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

func GenesisTransaction(ietf Wallet) Transaction {
	var gtx Transaction
	gtx.Input = []TransactionInput{} 
	gtx.Output = []TransactionOutput{
		TransactionOutput{ietf.GetPublicString(),".com","9.9.9.9"},
		TransactionOutput{ietf.GetPublicString(),".gov","8.8.8.8"},
		TransactionOutput{ietf.GetPublicString(),".org","7.7.7.7"},
	}
	msg := gtx.Input.InputString() + gtx.Output.OutputString()
	hash := sha256.Sum256([]byte(msg))
	gtx.Number = hex.EncodeToString(hash[:])
	gtx.Signature = ""
	return gtx
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

	IETF, err := CreateWallet()
	if err != nil {
		panic(err)
	}

	go func() {
		t := time.Now()
		genesisBlock := Block{0, t.String(), GenesisTransaction(IETF), "", "",difficulty,0.0}
		spew.Dump(genesisBlock)
		Blockchain = append(Blockchain, genesisBlock)

		selfServer := DNSServer{"127.0.0.1","Hello World"}
		DNSServerList = append(DNSServerList, selfServer)

	}()
	log.Fatal(run())

}
