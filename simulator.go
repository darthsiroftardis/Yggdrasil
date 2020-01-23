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

func (w Wallet) CreateNewTransaction(PublicKeyAddress string, oldTx Transaction) Transaction {
	var newTx Transaction
	newTx.Input = []TransactionInput{
		TransactionInput{oldTx.Number, 
			[]TransactionOutput{
				oldTx.Output[0],
			},
		},
	}
	newTx.Output = []TransactionOutput{
		TransactionOutput{PublicKeyAddress,"ns.hallows.com","1.1.1.1"},
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



func main() {
	IETF, err := CreateWallet()
	if err != nil {
		panic(err)
	}

	HallowsWallet, err := CreateWallet()
	if err != nil {
		panic(err)
	}

	gtx := GenesisTransaction(IETF)
	newTx := IETF.CreateNewTransaction(HallowsWallet.GetPublicString(),gtx)

	spew.Dump(gtx)
	spew.Dump(newTx)

	valid := newTx.ValidateTransaction()
	fmt.Println(valid)

	txBytes, err := asn1.Marshal(newTx)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post("http://localhost:8080/","*/*",bytes.NewBuffer(txBytes))
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))

	

}


