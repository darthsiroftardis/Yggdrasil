package main

import (
    "fmt"
    "io/ioutil"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "encoding/hex"
)


type Transaction struct {
	Number		string
	Input		inputList
	Output		outputList
	Signature 	string
}

type TransactionOutput struct {
	value 		float64
	PublicKey 	string
	Hostname	string
	IpAddr		string
}

type outputList []TransactionOutput

func (outputs outputList) OutputString() string {
	var outputString string
	for _,output := range outputs {
		str_value := fmt.Sprintf("%x", output.value)
		outputString += str_value
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


func GenesisTransaction() Transaction {
	var gtx Transaction
	gtx.Input = []TransactionInput{} 
	gtx.Output = []TransactionOutput{
		TransactionOutput{10.0,"ns.google.com","9.9.9.9",""},
		TransactionOutput{10.0,"ns.hallows.com","8.8.8.8",""},
		TransactionOutput{10.0,"ns.transistor.com","7.7.7.7",""},
	}
	msg := gtx.Input.InputString() + gtx.Output.OutputString()
	h := sha256.New()
	h.Write([]byte(msg))
	gtx.Number = fmt.Sprintf("%x",h.Sum(nil))
	gtx.Signature = ""
	return gtx
}








func check(e error) {
	if e != nil {
		panic(e)
	}
}

func loadKeys() (privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, pubBytes []byte) {
	bytePriv, err := ioutil.ReadFile("privateKey")
	if err != nil {
		panic(err)
	} 
	bytePub, err := ioutil.ReadFile("publicKey")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(bytePriv)
	x509Encoded := block.Bytes
	privateKey,_ = x509.ParseECPrivateKey(x509Encoded)

	blockPub, _:= pem.Decode(bytePub)
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey, bytePub

}

func main() {
	privateKey, publicKey, bytePub := loadKeys()
	publicAddress := hex.EncodeToString(bytePub)

	msg := "Testing message"
	hash := sha256.Sum256([]byte(msg))
	r,s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)
	valid := ecdsa.Verify(publicKey, hash[:], r, s)
	fmt.Println("Signature verified", valid)
	fmt.Printf("Public Address is [%s]\n", publicAddress)

	gtx := GenesisTransaction()

	fmt.Println(gtx)




}


