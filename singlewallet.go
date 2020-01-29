package main


import(
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/hex"
	"crypto/elliptic"
	"math/big"
	"context"
	"fmt"
	"log"
	"bufio"
	"os"
	"bytes"
	"strings"
	"net/http"
	"strconv"
	"io/ioutil"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/davecgh/go-spew/spew"

)




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

func (tx Transaction) ValidateTransaction() (bool) {
	signatureString := tx.Signature
	signatureBytes,err := hex.DecodeString(signatureString)
	if err != nil {
		panic(err)
	}
	signature := ECDSASignature{}
	_,err = asn1.Unmarshal(signatureBytes, &signature)

	msg := tx.Input.InputString() + tx.Output.OutputString() 
	hash := sha256.Sum256([]byte(msg))
	if err != nil {
		panic(err)
	}

	log.Println("SIGN")
	log.Println(signature.R,signature.S)
	log.Println("HASH")
	log.Println(hash)


	verificationKey := tx.RetrievePublicKey()
	valid := ecdsa.Verify(verificationKey, hash[:], signature.R, signature.S)
	return valid
}




func CreateWallet() (Wallet,error) {
	var w Wallet	
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Wallet{},err
	}
	w.privateKey = priv
	w.publicKeyBytes = elliptic.Marshal(priv.PublicKey, priv.PublicKey.X, priv.PublicKey.Y)
	//fmt.Println(w.publicKeyBytes)
	return w,nil
}


func (w Wallet) GetPublicString() string {
	publicKeyString := hex.EncodeToString(w.publicKeyBytes)
	return publicKeyString
} 

func (w Wallet) CreateNewTransaction(PublicKeyAddress string, inputs inputList) Transaction {
	reader := bufio.NewReader(os.Stdin)
	var newTx Transaction
	newTx.Input = inputs
	fmt.Printf("Enter Hostname:")
	ipHostname, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	ipHostname = strings.Replace(ipHostname,"\n","",-1)
	fmt.Printf("Enter IP Address:")
	ipIPAddr, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	ipIPAddr = strings.Replace(ipIPAddr,"\n","",-1)
	newTx.Output = outputList{
		TransactionOutput{
			PublicKeyAddress,
			ipHostname,
			ipIPAddr,
		},
	}
	msg := newTx.Input.InputString() + newTx.Output.OutputString()
	hash := sha256.Sum256([]byte(msg))
	log.Println("CREATED HASH")
	log.Println(hash)
	r,s, err := ecdsa.Sign(rand.Reader, w.privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	log.Println("CREATED SIGN")
	log.Println(r,s)
	sig_byte, err := asn1.Marshal(ECDSASignature{r,s})
	if err != nil {
		panic(err)
	}
	newTx.Signature = hex.EncodeToString(sig_byte)
	numHash := sha256.Sum256(sig_byte)
	newTx.Number = hex.EncodeToString(numHash[:])
	return newTx

}


type DNSEntry struct {
	Hostname 	string
	IpAddr		string
}

type DNSEntryList []DNSEntry

type Block struct {
	Index      int
	Timestamp  string
	Tx         Transaction
	Hash       string
	PrevHash   string
	Difficulty int
	Nonce      float64
}

type Blockchain []Block

type User struct {
	Name 				string
	UserWallet			Wallet
	PublicKeyAddress 	string
	OwnedEntry			DNSEntryList
}

func RetrieveWallet(priv, pub string) Wallet {
	var newWallet Wallet
	data, err := hex.DecodeString(priv)
	if err != nil {
		panic(err)
	}
	newWallet.privateKey,_ = x509.ParseECPrivateKey(data)
	newWallet.publicKeyBytes, err = hex.DecodeString(pub)
	if err != nil {
		panic(err)
	}
	return newWallet

}


func RetrieveUser(wf WalletFile) User {
	var newUser User
	newUser.Name = wf.Name
	newUser.UserWallet = RetrieveWallet(wf.PrivateKeyString, wf.PublicKeyString)
	newUser.PublicKeyAddress = wf.PublicKeyString
	return newUser
}


type WalletFile struct {
	Name 				string
	PrivateKeyString 	string
	PublicKeyString 	string
}

func (user User) MakeTransaction(address string) {
	var blockchain Blockchain
	reader := bufio.NewReader(os.Stdin)
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://localhost:8080/",nil)
	if err != nil {
		panic(err)
	}
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err = json.Unmarshal(body, &blockchain); err != nil {
		panic(err)
	}

	if len(blockchain) == 0 {
		/*fmt.Println("Create Genesis Transaction")
		fmt.Println("Creating TLDs")
		gtx := GenesisTransaction(user.UserWallet)
		spew.Dump(gtx)
		sendTx(gtx) */
	}	else if len(blockchain) == 1{
		fmt.Println("Select Genesis Output")
		for i, output := range blockchain[0].Tx.Output {
			fmt.Printf("[%d]||TLD:[%s]|IP:[%s]|Address:[%s]\n",i, output.Hostname, output.IpAddr,output.PublicKey)
		}
		selection, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		selection = strings.Replace(selection,"\n","",-1)
		j,err := strconv.Atoi(selection)
		if err != nil {
			panic(err)
		}
		input := TransactionInput{blockchain[0].Tx.Number, outputList{blockchain[0].Tx.Output[j]}}
		inputs := inputList{input}
		
		newTx := user.UserWallet.CreateNewTransaction(address, inputs)
		spew.Dump(newTx)
		if newTx.ValidateTransaction() != true {
			log.Fatal("Error")
		}
		sendTx(newTx)
	} else if len(blockchain) > 1 {
		log.Println("CYCLING THROUGH TO CHECK OWNED INPUTS")
		oMap := make(map[int]TransactionOutput)
		nMap := make(map[int]string)
		i := 1
		for _,block := range blockchain {
			fmt.Println("Select an owned input")
			for _,output := range block.Tx.Output{
				if strings.Compare(user.PublicKeyAddress, output.PublicKey) == 0 {
					fmt.Printf("[%d]|| Hostname:[%s]<-->IP:[%s]\n",i,output.Hostname,output.IpAddr)
					oMap[i] = output
					nMap[i] = block.Tx.Number
					i += 1
				}
			}
		}
		fmt.Printf("Enter Selection:")
		selection, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		selection = strings.Replace(selection,"\n","",-1)
		intSelection, err := strconv.Atoi(selection)
		if err != nil {
			panic(err)
		}
		input := TransactionInput{nMap[intSelection],outputList{oMap[intSelection]}}
		inputs := inputList{input}
		newTx := user.UserWallet.CreateNewTransaction(address, inputs)
		spew.Dump(newTx)
		sendTx(newTx)	
	}	
}

func sendTx(tx Transaction) {
	client := &http.Client{}
	txBytes, err := asn1.Marshal(tx)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/", bytes.NewBuffer(txBytes))
	if err != nil {
		panic(err)
	}
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	spew.Dump(response)
	//Sync()
}







func main() {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB")

	collection := client.Database("test").Collection("users")
	
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter User Name:")
	text, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	text = strings.Replace(text,"\n","",-1)

	var result WalletFile
	filter := bson.D{{"name",text}}
	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found one: %+v\n", result)
	
	log.Println(result.PrivateKeyString)
	log.Println(result.PublicKeyString)

	user := RetrieveUser(result)
	log.Println(user.UserWallet.privateKey)


	log.Println("TESTING SIGNING")

	msg := "hello"
	hash := sha256.Sum256([]byte(msg))
	r,s, err := ecdsa.Sign(rand.Reader, user.UserWallet.privateKey, hash[:])
	if err != nil {
		panic(err)
	}

	data, err := hex.DecodeString(user.PublicKeyAddress)
	if err != nil {
		panic(err)
	}

	x,y := elliptic.Unmarshal(elliptic.P256(), data)
	verificationKey := &ecdsa.PublicKey{
		elliptic.P256(), x, y,
	}
	valid := ecdsa.Verify(verificationKey, hash[:], r, s)
	if valid == false {
		log.Fatal("SIGNING FAILED")
	} 

	log.Println("SIGNING AVAILABLE")
	

	fmt.Println("Enter a User Name for their PublicKey")
	text, err = reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	text = strings.Replace(text,"\n","",-1)
	filter = bson.D{{"name",text}}

	var receiver WalletFile

	err = collection.FindOne(context.TODO(), filter).Decode(&receiver)
	if err != nil {
		log.Fatal(err)
	}

	user.MakeTransaction(receiver.PublicKeyString)

	err = client.Disconnect(context.TODO())

	if err != nil {
	    log.Fatal(err)
	}
	fmt.Println("Connection to MongoDB closed.")



}




