# Blockchain – Cosmos SDK and Golang

__0 __0 __222

## Overview

Cosmos is a decentralized network of independent blockchains which are powered by the Byzantine Fault Tolerance (BFT) consensus algorithm. The Cosmos SDK enables the creation of these blockchain applications. In this blog post, I would like to share with you some of these Cosmos SDK functions.

The documentation of Cosmos SDK can be found at <https://pkg.go.dev/github.com/cosmos/cosmos-sdk>.

The following code samples were written in Golang and Cosmos SDK v0.45.4.

###

## Code Samples

### Initialize New Keyring

The keyring holds the private/public keypairs used for interactions with a node.

```javascript
import (
    "strings"
    "github.com/cosmos/cosmos-sdk/crypto/keyring"
    "github.com/cosmos/cosmos-sdk/types"
)

func NewKeyring() (keyring.Keyring, error) {
    var kr keyring.Keyring
    keyringPassword := "password"
    runtimeHomeDir := "~/.cosmosHome"
    reader := strings.NewReader("")
    reader.Reset(keyringPassword + "\n")
    kr, err := keyring.New(
        types.KeyringServiceName(),
        keyring.BackendTest
        runtimeHomeDir,
        reader,
    )
    if err != nil {
        return kr, err
    }
    return kr, nil
}
```

 

### Create Account

An account designates the private/public keypairs. The public key can be derived to generate various Addresses which are used to identify the users in the blockchain.

```javascript
import (
    "github.com/cosmos/cosmos-sdk/crypto/keyring"
)

func CreateAccount() (string, error) {
    keyringPassword := "password"
    kr, err = NewKeyring()
    if err != nil {
        return "", err
    }
    algo, _ := kr.SupportedAlgorithms()
    signingAlgo, err := keyring.NewSigningAlgoFromString("secp256k1", algo)
    if err != nil {
        return "", err
    }
    uid := genUID()
    mnemonicInfo, _, err := kr.NewMnemonic(uid, keyring.English, "", keyringPassword, signingAlgo)
    if err != nil {
        return "", err
    }
    return mnemonicInfo.GetAddress().String(), nil
}

func genUID() string {
//  Generate a string composed of 40 randomized alphanumeric characters.
}
```

 

### Create GRPC Connection

Queries can be performed through a GRPC connection.

```javascript
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

/* Create a GRPC client connnection with TLS. */
func CreateGrpcConnTls() (*grpc.ClientConn, error) {
    var grpcConn *grpc.ClientConn
    var err error
//  Specify the fully qualified hostname and port of the validator node.
    grpcHost := "…Hostname…"
    tlsCfg := &tls.Config{
        InsecureSkipVerify: true,
    }
    grpcConn, err = grpc.Dial(
        grpcHost,
        grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
    )
    return grpcConn, err
}

/* Create a GRPC client connnection without TLS. */
func CreateGrpcConn() (*grpc.ClientConn, error) {
    var grpcConn *grpc.ClientConn
    var err error
//  Specify the fully qualified hostname and port of the validator node.
    grpcHost := "…Hostname…"
    grpcConn, err = grpc.Dial(
        grpcHost,
        grpc.WithInsecure(),
    )
    return grpcConn, err
}
```

 

### Get Node Information

Getting the information of a node.

```javascript
import (
    "github.com/cosmos/cosmos-sdk/client/grpc/tmservice"
    "github.com/tendermint/tendermint/proto/tendermint/p2p"
)

func GetNodeInfo() (*p2p.DefaultNodeInfo, error) {
    var nodeInfo *p2p.DefaultNodeInfo
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return nodeInfo, err
    }
    defer grpcConn.Close()
    serviceClient := tmservice.NewServiceClient(grpcConn)
    nodeInfoRes, err := serviceClient.GetNodeInfo(
        context.Background(),
        &tmservice.GetNodeInfoRequest{},
    )
    if err != nil {
        return nodeInfo, err
    }
    nodeInfo = nodeInfoRes.GetDefaultNodeInfo()
    return nodeInfo, nil
}
```

 

### Get Latest Block

Getting information of the latest block.

```javascript
import (
    "context"
    "encoding/base64"
    "github.com/cosmos/cosmos-sdk/client/grpc/tmservice"
)

func GetLatestBlock() (*tmservice.GetLatestBlockResponse, error) {
    var latestBlockRes *tmservice.GetLatestBlockResponse
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return latestBlockRes, err
    }
    defer grpcConn.Close()
    serviceClient := tmservice.NewServiceClient(grpcConn)
    latestBlockRes, err = serviceClient.GetLatestBlock(
        context.Background(),
        &tmservice.GetLatestBlockRequest{},
    )
    if err != nil {
        return latestBlockRes, err
    }
    return latestBlockRes, nil
}

/* Get the attributes */
latestBlockRes, err := GetLatestBlock()
block := latestBlockRes.GetBlock() // Type: Block
header := block.GetHeader() // Type: Header
height := header.GetHeight()
dataHash := header.GetDataHash()
blockId := latestBlockRes.GetBlockId() // Type: BlockID
blockIdHash := base64.StdEncoding.EncodeToString(blockId.GetHash())
```

 

### Get Block by Height

Getting the block information by the height.

```abap
import (
    "context"
    "encoding/base64"
    "github.com/cosmos/cosmos-sdk/client/grpc/tmservice"
)

func GetBlockByHeight(height int64) (*tmservice.GetBlockByHeightResponse, error) {
    var blockRes *tmservice.GetBlockByHeightResponse
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return blockRes, err
    }
    defer grpcConn.Close()
    serviceClient := tmservice.NewServiceClient(grpcConn)
    blockRes, err = serviceClient.GetBlockByHeight(
        context.Background(),
        &tmservice.GetBlockByHeightRequest{Height: height},
    )
    if err != nil {
        return blockRes, err
    }
    return blockRes, nil
}

/* Get the attributes */
height int64 := 12345
blockRes, err := GetBlockByHeight(height)
block := blockRes.GetBlock() // Type: Block
header := block.GetHeader() // Type: Header
blockId := blockRes.GetBlockId() // Type: BlockID
blockIdHash := base64.StdEncoding.EncodeToString(blockId.GetHash())
```

 

### Get Balance

Getting the balance of an account address.

```javascript
import (
    sdktypes  "github.com/cosmos/cosmos-sdk/types"
    banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

func GetBalance(accountAddress, denom string) (*sdktypes.Coin, error) {
    var balance *sdktypes.Coin
    addr, err := sdktypes.AccAddressFromBech32(accountAddress)
    if err != nil {
        return balance, err
    }
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return balance, err
    }
    defer grpcConn.Close()
    bankClient := banktypes.NewQueryClient(grpcConn)
    balanceRes, err := bankClient.Balance(
        context.Background(),
        &banktypes.QueryBalanceRequest{Address: addr.String(), Denom: denom},
    )
    if err != nil {
        return balance, err
    }
    balance = balanceRes.GetBalance()
    return balance, nil
}

/* Get the attributes */
accountAddress := "……"
denom := "……"
balance, err := GetBalance(accountAddress, denom) // Type: Coin
amount := balance.Amount
```

 

### Create Transaction

Creating a transaction is a 2-step process. First, a signed transaction is created. Second, the signed transaction is broadcasted.

```javascript
func createTxn() (string, error) {
    txBytes, err := CreateSignedTxn()
    if err != nil {
        return "", err
    }
    txHash, _, err := BroadcastSignedTxn(txBytes)
    if err != nil {
        return "", err
    }
    return txHash, nil
}
```

 

### Create Signed Transaction

The transaction example is to send tokens from account A to account B. For simplicity, some error checking is skipped in the following code snippet.

```javascript
Import (
                "github.com/cosmos/cosmos-sdk/client/tx"
                "github.com/cosmos/cosmos-sdk/crypto"
    cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
    sdktypes    "github.com/cosmos/cosmos-sdk/types"
                "github.com/cosmos/cosmos-sdk/types/tx/signing"
    authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
    banktypes   "github.com/cosmos/cosmos-sdk/x/bank/types"
)

func CreateSignedTxn() ([]byte, error) {
    encodingConfig := cosmoscmd.MakeEncodingConfig(catxapp.ModuleBasics)
    txConfig := encodingConfig.TxConfig
    txBuilder := txConfig.NewTxBuilder()
    kr, err := NewKeyring()
//  Specify the from account address.
    fromAddr, err := sdktypes.AccAddressFromBech32("…From Address…")
//  Specify the to account address.
    toAddr, err := sdktypes.AccAddressFromBech32("…To Address…")
//  Specify the amount of tokens to be sent.
    amount := ……
//  Specify the denomination.
    coin := sdktypes.NewInt64Coin("…Denomination…", amount)
    coins := sdktypes.NewCoins(coin)
    msg := banktypes.NewMsgSend(fromAddr, toAddr, coins)
    if err := txBuilder.SetMsgs(msg); err != nil { return nil, err }
//  Specify the fee.
    fee := ……
//  Specify the denomination.
    feeAmt := sdktypes.Coin{Denom: "…Denomination…", Amount: sdktypes.NewInt(fee)}
    feeAmount := sdktypes.NewCoins(feeAmt)
    txBuilder.SetFeeAmount(feeAmount)
//  Specify the gas limit.
    gasLimit := ……
    txBuilder.SetGasLimit(gasLimit)
    keyInfo, err := kr.KeyByAddress(fromAddr)
//  Specify the passphrase.
    exportedPrivateKey, err := kr.ExportPrivKeyArmor(keyInfo.GetName(), "…Passphrase…")
//  Specify the passphrase.
    privateKey, _, err := crypto.UnarmorDecryptPrivKey(exportedPrivateKey, "…Passphrase…"])
//  Specify the from account address.
    account, err := GetAccount("…From Address…")
    accNumber := account.AccountNumber
    accSequence := account.Sequence
    privKeyList := []cryptotypes.PrivKey{privateKey}
    accNumberList := []uint64{accNumber}
    accSeqList := []uint64{accSequence}
/*  First round: Gather all signer infos. */
    var signatureList []signing.SignatureV2
    for idx, privKey := range privKeyList {
        sig := signing.SignatureV2{
            PubKey: privKey.PubKey(),
            Data: &signing.SingleSignatureData{
                SignMode:  encodingConfig.TxConfig.SignModeHandler().DefaultMode(),
                Signature: nil,
            },
            Sequence: accSeqList[idx],
        }
        signatureList = append(signatureList, sig)
    }
    if err := txBuilder.SetSignatures(signatureList...); err != nil { return nil, err }
/*  Second round: Signed by each signer. */
    var signingList []signing.SignatureV2
    for idx, privKey := range privKeyList {
        signerData := authsigning.SignerData {
        //  Specify the chain ID.
            ChainID:       "……",
            AccountNumber: accNumberList[idx],
            Sequence:      accSeqList[idx],
        }
        signMode := encodingConfig.TxConfig.SignModeHandler().DefaultMode()
        sig, err := tx.SignWithPrivKey(signMode, signerData, txBuilder, privKey,
        encodingConfig.TxConfig, accSeqList[idx])
        signingList = append(signingList, sig)
    }
    if err := txBuilder.SetSignatures(signingList...); err != nil { return nil, err }
    txBytes, err := encodingConfig.TxConfig.TxEncoder()(txBuilder.GetTx())
    return txBytes, nil
}
```

 

### Broadcast Signed Transaction

Broadcasting a signed transaction.

```javascript
import (
    "context"
    "strconv"
    "github.com/cosmos/cosmos-sdk/types/tx"
)

func BroadcastSignedTxn(txBytes []byte) (string, int64, error) {
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return "", int64(0), err
    }
    defer grpcConn.Close()
    serviceClient := tx.NewServiceClient(grpcConn)
    broadcastTxRes, err := serviceClient.BroadcastTx(
        context.Background(),
        &tx.BroadcastTxRequest{
            Mode:    tx.BroadcastMode_BROADCAST_MODE_BLOCK,
            TxBytes: txBytes,
        },
    )
    if err != nil {
        return "", int64(0), err
    }
    txResponse := broadcastTxRes.GetTxResponse()
    if txResponse.Code != 0 {
        return "", int64(0),
        errors.New("TxResponse.Code: " + strconv.FormatUint(uint64(txResponse.Code), 10))
    }
    return txResponse.TxHash, txResponse.Height, nil
}
```

 

### Get Transaction by Hash

Getting transaction information by the transaction hash.

```javascript
import (
             "context"
    sdktypes "github.com/cosmos/cosmos-sdk/types"
    txtypes  "github.com/cosmos/cosmos-sdk/types/tx"
)

func GetTxnByHash(txHash string) (*sdktypes.TxResponse, error) {
    var txResponse *sdktypes.TxResponse
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return txResponse, err
    }
    defer grpcConn.Close()
    serviceClient := txtypes.NewServiceClient(grpcConn)
    txRes, err := serviceClient.GetTx(
        context.Background(),
        &txtypes.GetTxRequest{Hash: txHash},
    )
    if err != nil {
        return txResponse, err
    }
    txResponse = txRes.GetTxResponse()
    return txResponse, nil
}

/* Get the attributes */
txHash := "……"
txRes, err := GetTxnByHash(txHash)
height := txRes.Height
```

 

### Get Account

Getting the information of an account.

```javascript
import (
    "github.com/cosmos/cosmos-sdk/x/auth/types"
)

func GetAccount(accountAddress string) (types.BaseAccount, error) {
    var baseAccount types.BaseAccount
    addr, err := sdktypes.AccAddressFromBech32(accountAddress)
    if err != nil {
        return baseAccount, err
    }
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return baseAccount, err
    }
    defer grpcConn.Close()
    accountClient := types.NewQueryClient(grpcConn)
    accountRes, err := accountClient.Account(
        context.Background(),
        &types.QueryAccountRequest{Address: addr.String()},
    )
    if err != nil {
        return baseAccount, err
    }
    accountData := accountRes.GetAccount().Value
    if err := baseAccount.XX_Unmarshal(accountData); err != nil {
        return baseAccount, err
    }
    return baseAccount, nil
}
```

 

### Get Validator Set

Getting the information of the validator set.

```javascript
import (
    "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func GetValidatorSet() ([]types.Validator, error) {
    var validatorList []types.Validator
    grpcConn, err := CreateGrpcConnTls()
    if err != nil {
        return validatorList, err
    }
    defer grpcConn.Close()
    queryClient := types.NewQueryClient(grpcConn)
    validatorsRes, err := queryClient.Validators(
        context.Background(),
        &types.QueryValidatorsRequest{},
    if err != nil {
        return validatorList, err
    }
    validatorList = validatorsRes.GetValidators()
    return validatorList, nil
}
```

 

## Type Structs

### Type: Block

Block defines the atomic unit of a Tendermint blockchain.

The structure of type Block is defined as:

```javascript
type Block struct {
    Header `json:"header"`
    ……
}
```

For details, see:

<https://pkg.go.dev/github.com/tendermint/tendermint@v0.34.19/types#Block>

<https://github.com/tendermint/tendermint/blob/v0.34.19/proto/tendermint/types/block.pb.go>

 

### Type: BlockID

The structure of type BlockID is defined as:

```javascript
type BlockID struct {
    Hash tmbytes.HexBytes `json:"hash"`
    ……
}
```

For details, see:

<https://pkg.go.dev/github.com/tendermint/tendermint@v0.34.19/types#BlockID>

<https://github.com/tendermint/tendermint/blob/v0.34.19/proto/tendermint/types/types.pb.go>

 

### Type: Coin

Coin defines a token with a denomination and an amount.

The structure of type Coin is defined as:

```javascript
type Coin struct {
    Denom  string `json:"denom,omitempty"`
    Amount Int    `json:"amount"`
}
```

For details, see:

<https://pkg.go.dev/github.com/cosmos/cosmos-sdk@v0.45.4/types#Coin>

<https://github.com/cosmos/cosmos-sdk/blob/v0.45.4/types/coin.pb.go>

 

### Type: Header

Header defines the structure of a Tendermint block header.

The structure of type Header is defined as:

```javascript
type Header struct {
    Height   int64            `json:"height"`
    DataHash tmbytes.HexBytes `json:"data_hash"`
    ……
}
```

For details, see:

<https://pkg.go.dev/github.com/tendermint/tendermint@v0.34.19/types#Header>

<https://github.com/tendermint/tendermint/blob/v0.34.19/proto/tendermint/types/types.pb.go>

 

### Type: QueryBalanceRequest

The structure of type QueryBalanceRequest is defined as:

```javascript
type QueryBalanceRequest struct {
    Address string `json:"address,omitempty"`
    Denom   string `json:"denom,omitempty"`
}
```

For details, see:

<https://pkg.go.dev/github.com/cosmos/cosmos-sdk@v0.45.4/x/bank/types#QueryBalanceRequest>

<https://github.com/cosmos/cosmos-sdk/blob/v0.45.4/x/bank/types/query.pb.go>

 

### Type: QueryBalanceResponse

The structure of type QueryBalanceResponse is defined as:

```javascript
type QueryBalanceResponse struct {
    Balance *types.Coin `json:"balance,omitempty"`
}
```

For details, see:

<https://pkg.go.dev/github.com/cosmos/cosmos-sdk@v0.45.4/x/bank/types#QueryBalanceResponse>

<https://github.com/cosmos/cosmos-sdk/blob/v0.45.4/x/bank/types/query.pb.go>
