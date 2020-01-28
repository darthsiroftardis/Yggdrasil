package main

import (
	"fmt"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"	
	"math/big"
	"net/http"
	"bytes"
	"io/ioutil"
	"encoding/json"
	"log"
	"strconv"
	"os"
	"strings"
	"bufio"



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

	hash, err := hex.DecodeString(tx.Number)

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
	newTx.Number = hex.EncodeToString(hash[:])
	r,s, err := ecdsa.Sign(rand.Reader, w.privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	sig_byte, err := asn1.Marshal(ECDSASignature{r,s})
	if err != nil {
		panic(err)
	}
	newTx.Signature = hex.EncodeToString(sig_byte)

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
		fmt.Println("Create Genesis Transaction")
		fmt.Println("Creating TLDs")
		gtx := GenesisTransaction(user.UserWallet)
		spew.Dump(gtx)
		sendTx(gtx)
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
		sendTx(newTx)
	} else if len(blockchain) > 1 {
		log.Println("CYCLING THROUGH TO CHECK OWNED INPUTS")
		oMap := make(map[int]TransactionOutput)
		nMap := make(map[int]string)
		for _,block := range blockchain {
			fmt.Println("Select an owned input")
			i := 1
			if strings.Compare(user.PublicKeyAddress, block.Tx.Output[0].PublicKey) == 0 {
				fmt.Printf("[%d]|| Hostname:[%s]<-->IP:[%s]",i,block.Tx.Output[0].Hostname,block.Tx.Output[0].IpAddr)
				oMap[i] = block.Tx.Output[0]
				nMap[i] = block.Tx.Number
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
}


func (user User) DisplayBalance() {
	fmt.Println(user.OwnedEntry)
	for _,entry := range user.OwnedEntry {
		fmt.Printf("Hostname:[%s]||IP Address:[%s]\n",entry.Hostname, entry.IpAddr)
	}
}


func PassThrough(user User,users UserList) {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		fmt.Println("Current Options")
		fmt.Print("[1]Create a Transaction\n[2]Check Wallet Balance\n[3]Select New Wallet\n")
		fmt.Print("Enter an Option:")
		text, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		text = strings.Replace(text,"\n","",-1)
		if strings.Compare("1",text) == 0 {
			fmt.Println("Select a Receiver")
			for i,singleUser := range users {
				fmt.Printf("[%d] || [%s]\n", i, singleUser.Name)
			}
			fmt.Print("Enter Receiver:")
			selection, err := reader.ReadString('\n')
			if err != nil {
				panic(err)
			}
			selection = strings.Replace(selection,"\n","",-1)
			intSelection, err := strconv.Atoi(selection)
			if err != nil {
				panic(err)
			}
			user.MakeTransaction(users[intSelection].PublicKeyAddress)
		} else if strings.Compare("2", text) == 0 {
			fmt.Println("Current Balance")
			user.DisplayBalance()
		} else if strings.Compare("3", text) == 0 {
			fmt.Println("Wallet updated")
			break
		}
	}
}


func interactiveMode(users UserList) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Current User List")
	for i,user := range users {
		fmt.Printf("[%d]|| Name:[%s]\n",i,user.Name)
	}
	for {
		fmt.Print("Select a user with their corresponding number OR Enter 'EXIT' to Quit:")
		text, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		text = strings.Replace(text,"\n","",-1)
		if strings.Compare("EXIT",text) == 0 {
			fmt.Println("Exiting Interactive Mode")
			break
		}
		for i,_ := range users {
			if strings.Compare(strconv.Itoa(i), text) == 0 {
				fmt.Printf("Selected user:[%s]\n", users[i].Name)
				PassThrough(users[i], users)
			}
		}
	}
}

func check(address string) (bool,int) {
	for i := 0; i < len(users); i++ {
		if strings.Compare(users[i].PublicKeyAddress, address) == 0 {
			return true,i 
		}
	}
	return false, -1
}




func Sync()  {
	var blockchain Blockchain
	client := http.Client{}
	req, err := http.NewRequest("GET","http://localhost:8080/",nil)
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
	if err = json.Unmarshal(response, &blockchain); err != nil {
		panic(err)
	}
	for _,block := range blockchain {
		present,i := check(block.Tx.Output[0].PublicKey)
		if present {
			users[i].OwnedEntry = append(users[i].OwnedEntry, DNSEntry{
				block.Tx.Output[0].Hostname,
				block.Tx.Output[0].IpAddr,
			})
			log.Println(users[i].OwnedEntry)	
		}
	}


}

var users UserList

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("DNS Wallet testing utility")
	fmt.Println("Available Options")
	fmt.Printf("[1]Create a New User\n[2]See Current Users\n[3]Interact with Wallet\n[4]Sync With Blockchain\n[5]Quit\n")
	for {
		fmt.Print("Enter an Option:")
		text, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		text = strings.Replace(text,"\n","",-1)
		if strings.Compare("1",text) == 0 {
			fmt.Println("Creating a new Wallet")
			fmt.Printf("Enter User Name:")
			name, _ := reader.ReadString('\n')
			name = strings.Replace(name,"\n","",-1)
			users = append(users,CreateNewUser(name))
		} else if strings.Compare("2",text) == 0 {
			fmt.Println("Current User List")
			users.Display()
		} else if strings.Compare("5", text) == 0 {
			fmt.Println("Exiting")
			break
		} else if strings.Compare("3", text) == 0 {
			fmt.Println("Current Wallets")
			interactiveMode(users)
		} else if strings.Compare("4", text) == 0 {
			fmt.Println("Sync in progress")
			Sync()
			log.Println("USERS")
			log.Println(users)
		}
	}
}