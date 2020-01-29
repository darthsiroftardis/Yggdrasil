package main


import(
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"crypto/elliptic"
	"math/big"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"bufio"
	//"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

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


type WalletFile struct {
	Name 				string
	PrivateKeyString 	string
	PublicKeyString 	string
}

func makeFile(user User) WalletFile {
	var newFile WalletFile
	newFile.Name = user.Name
	data, err := x509.MarshalECPrivateKey(user.UserWallet.PrivateKey)
	if err != nil {
		panic(err)
	}
	newFile.PrivateKeyString = hex.EncodeToString(data)
	newFile.PublicKeyString = user.PublicKeyAddress 
	return newFile
}



type Wallet struct {
	PrivateKey 		*ecdsa.PrivateKey
	PublicKeyBytes  []byte
}

type ECDSASignature struct {
	R, S *big.Int
}


func CreateWallet() (Wallet,error) {
	var w Wallet	
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Wallet{},err
	}
	w.PrivateKey = priv
	w.PublicKeyBytes = elliptic.Marshal(priv.PublicKey, priv.PublicKey.X, priv.PublicKey.Y)
	//fmt.Println(w.publicKeyBytes)
	return w,nil
}

func (w Wallet) GetPublicString() string {
	publicKeyString := hex.EncodeToString(w.PublicKeyBytes)
	return publicKeyString
} 

type User struct {
	Name 				string
	UserWallet			Wallet
	PublicKeyAddress 	string
	//OwnedEntry			DNSEntryList
}

type UserList []User

func(users UserList) Display() {
	for i, user := range users {
		fmt.Printf("[%d] || Name:[%s] || Public Address[%s]\n",i,user.Name, user.PublicKeyAddress)
	}
}


func CreateNewUser(name string) User {
	var newUser User
	newUser.Name = name
	newUser.UserWallet,_ = CreateWallet()
	newUser.PublicKeyAddress = newUser.UserWallet.GetPublicString()
	fmt.Printf("New Wallet user with name:[%s] and Address:[%s] Created.\n", newUser.Name, newUser.PublicKeyAddress)
	return newUser
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
	for {
		fmt.Printf("Add a New User or press [EXIT] to Quit")
		text, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		text = strings.Replace(text,"\n","",-1)
		if strings.Compare("EXIT",text) == 0 {
			break
		}
		temp := CreateNewUser(text)
		userFile := makeFile(temp)	
		res, err := collection.InsertOne(context.TODO(), userFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(res)
	}
	err = client.Disconnect(context.TODO())

	if err != nil {
	    log.Fatal(err)
	}
	fmt.Println("Connection to MongoDB closed.")


}