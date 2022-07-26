// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package qtum

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ChainSafe/ChainBridge/connections/ethereum/egs"
	"github.com/ChainSafe/log15"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var BlockRetryInterval = time.Second * 5

type Connection struct {
	endpoint      string
	http          bool
	fromAddress   string
	bridgeAddress ethcommon.Address
	gasLimit      *big.Int
	maxGasPrice   *big.Int
	minGasPrice   *big.Int
	gasMultiplier *big.Float
	egsApiKey     string
	egsSpeed      string
	conn          *ethclient.Client
	rpcClient     *rpc.Client
	// signer    ethtypes.Signer
	opts     *bind.TransactOpts
	callOpts *bind.CallOpts
	nonce    uint64
	optsLock sync.Mutex
	log      log15.Logger
	stop     chan int // All routines should exit when this channel is closed
}

// NewConnection returns an uninitialized connection, must call Connection.Connect() before using.
func NewConnection(endpoint string, http bool, fromAddress string, bridgeAddress ethcommon.Address, log log15.Logger, gasLimit, maxGasPrice, minGasPrice *big.Int, gasMultiplier *big.Float, gsnApiKey, gsnSpeed string) *Connection {
	return &Connection{
		endpoint:      endpoint,
		http:          http,
		fromAddress:   fromAddress,
		bridgeAddress: bridgeAddress,
		gasLimit:      gasLimit,
		maxGasPrice:   maxGasPrice,
		minGasPrice:   minGasPrice,
		gasMultiplier: gasMultiplier,
		egsApiKey:     gsnApiKey,
		egsSpeed:      gsnSpeed,
		log:           log,
		stop:          make(chan int),
	}
}

// Connect starts the ethereum WS connection
func (c *Connection) Connect() error {
	c.log.Info("Connecting to qtum chain...", "url", c.endpoint)
	var err error
	// Start http or ws client
	if c.http {
		c.rpcClient, err = rpc.DialHTTP(c.endpoint)
	} else {
		c.rpcClient, err = rpc.DialContext(context.Background(), c.endpoint)
	}
	if err != nil {
		return err
	}
	c.conn = ethclient.NewClient(c.rpcClient)

	// Construct tx opts, call opts, and nonce mechanism
	opts, _, err := c.newTransactOpts(big.NewInt(0), c.gasLimit, c.maxGasPrice)
	if err != nil {
		return err
	}
	c.opts = opts
	c.nonce = 0
	c.callOpts = &bind.CallOpts{From: ethcommon.HexToAddress(c.fromAddress)}
	return nil
}

// newTransactOpts builds the TransactOpts for the connection's keypair.
func (c *Connection) newTransactOpts(value, gasLimit, gasPrice *big.Int) (*bind.TransactOpts, uint64, error) {
	address := ethcommon.HexToAddress(c.fromAddress)
	nonce, err := c.conn.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, 0, err
	}

	auth := &bind.TransactOpts{
		From: address,
		Context: context.Background(),
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = uint64(gasLimit.Int64())
	auth.GasPrice = gasPrice
	auth.Context = context.Background()

	return auth, nonce, nil
}

func (c *Connection) FromAddress() ethcommon.Address {
	return ethcommon.HexToAddress(c.fromAddress)
}

func (c *Connection) Client() *ethclient.Client {
	return c.conn
}

func (c *Connection) RpcClient() *rpc.Client {
	return c.rpcClient
}

func (c *Connection) Opts() *bind.TransactOpts {
	return c.opts
}

func (c *Connection) CallOpts() *bind.CallOpts {
	return c.callOpts
}

func (c *Connection) SafeEstimateGas(ctx context.Context) (*big.Int, error) {

	var suggestedGasPrice *big.Int

	// First attempt to use EGS for the gas price if the api key is supplied
	if c.egsApiKey != "" {
		price, err := egs.FetchGasPrice(c.egsApiKey, c.egsSpeed)
		if err != nil {
			c.log.Error("Couldn't fetch gasPrice from GSN", "err", err)
		} else {
			suggestedGasPrice = price
		}
	}

	// Fallback to the node rpc method for the gas price if GSN did not provide a price
	if suggestedGasPrice == nil {
		c.log.Debug("Fetching gasPrice from node")
		nodePriceEstimate, err := c.conn.SuggestGasPrice(context.TODO())
		if err != nil {
			return nil, err
		} else {
			suggestedGasPrice = nodePriceEstimate
		}
	}

	gasPrice := multiplyGasPrice(suggestedGasPrice, c.gasMultiplier)

	// Check we aren't exceeding our limit
	if gasPrice.Cmp(c.minGasPrice) == -1 {
		return c.minGasPrice, nil
	} else if gasPrice.Cmp(c.maxGasPrice) == 1 {
		return c.maxGasPrice, nil
	} else {
		return gasPrice, nil
	}
}

func (c *Connection) EstimateGasLondon(ctx context.Context, baseFee *big.Int) (*big.Int, *big.Int, error) {
	var maxPriorityFeePerGas *big.Int
	var maxFeePerGas *big.Int

	if c.maxGasPrice.Cmp(baseFee) < 0 {
		maxPriorityFeePerGas = big.NewInt(1000000000)
		maxFeePerGas = new(big.Int).Add(c.maxGasPrice, maxPriorityFeePerGas)
		return maxPriorityFeePerGas, maxFeePerGas, nil
	}

	maxPriorityFeePerGas, err := c.conn.SuggestGasTipCap(context.TODO())
	if err != nil {
		return nil, nil, err
	}

	maxFeePerGas = new(big.Int).Add(
		maxPriorityFeePerGas,
		new(big.Int).Mul(baseFee, big.NewInt(2)),
	)

	if maxFeePerGas.Cmp(maxPriorityFeePerGas) < 0 {
		return nil, nil, fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", maxFeePerGas, maxPriorityFeePerGas)
	}

	// Check we aren't exceeding our limit
	if maxFeePerGas.Cmp(c.maxGasPrice) == 1 {
		maxPriorityFeePerGas.Sub(c.maxGasPrice, baseFee)
		maxFeePerGas = c.maxGasPrice
	}
	return maxPriorityFeePerGas, maxFeePerGas, nil
}

func multiplyGasPrice(gasEstimate *big.Int, gasMultiplier *big.Float) *big.Int {

	gasEstimateFloat := new(big.Float).SetInt(gasEstimate)

	result := gasEstimateFloat.Mul(gasEstimateFloat, gasMultiplier)

	gasPrice := new(big.Int)

	result.Int(gasPrice)

	return gasPrice
}

// LockAndUpdateOpts acquires a lock on the opts before updating the nonce
// and gas price.
func (c *Connection) LockAndUpdateOpts() error {
	c.optsLock.Lock()

	head, err := c.conn.HeaderByNumber(context.TODO(), nil)
	if err != nil {
		c.UnlockOpts()
		return err
	}

	if head.BaseFee != nil {
		c.opts.GasTipCap, c.opts.GasFeeCap, err = c.EstimateGasLondon(context.TODO(), head.BaseFee)
		if err != nil {
			c.UnlockOpts()
			return err
		}

		// Both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) cannot be specified: https://github.com/ethereum/go-ethereum/blob/95bbd46eabc5d95d9fb2108ec232dd62df2f44ab/accounts/abi/bind/base.go#L254
		c.opts.GasPrice = nil
	} else {
		var gasPrice *big.Int
		gasPrice, err = c.SafeEstimateGas(context.TODO())
		if err != nil {
			c.UnlockOpts()
			return err
		}
		c.opts.GasPrice = gasPrice
	}

	nonce, err := c.conn.PendingNonceAt(context.Background(), c.opts.From)
	if err != nil {
		c.optsLock.Unlock()
		return err
	}
	c.opts.Nonce.SetUint64(nonce)
	return nil
}

func (c *Connection) UnlockOpts() {
	c.optsLock.Unlock()
}

// LatestBlock returns the latest block from the current chain
func (c *Connection) LatestBlock() (*big.Int, error) {
	header, err := c.conn.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	return header.Number, nil
}

// EnsureHasBytecode asserts if contract code exists at the specified address
func (c *Connection) EnsureHasBytecode(addr ethcommon.Address) error {
	code, err := c.conn.CodeAt(context.Background(), addr, nil)
	if err != nil {
		return err
	}

	if len(code) == 0 {
		return fmt.Errorf("no bytecode found at %s", addr.Hex())
	}
	return nil
}

// WaitForBlock will poll for the block number until the current block is equal or greater.
// If delay is provided it will wait until currBlock - delay = targetBlock
func (c *Connection) WaitForBlock(targetBlock *big.Int, delay *big.Int) error {
	for {
		select {
		case <-c.stop:
			return errors.New("connection terminated")
		default:
			currBlock, err := c.LatestBlock()
			if err != nil {
				return err
			}

			if delay != nil {
				currBlock.Sub(currBlock, delay)
			}

			// Equal or greater than target
			if currBlock.Cmp(targetBlock) >= 0 {
				return nil
			}
			c.log.Trace("Block not ready, waiting", "target", targetBlock, "current", currBlock, "delay", delay)
			time.Sleep(BlockRetryInterval)
			continue
		}
	}
}

// ensureContext is a helper method to ensure a context is not nil, even if the
// user specified it as such.
func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}


// Close terminates the client connection and stops any running routines
func (c *Connection) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
	close(c.stop)
}

// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

// curl --header 'Content-Type: application/json' --data '{"id":"10","jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0x9735887ba7bff92e62f00b221dc6daf3d5218e6f","gas":"0x6691b7","gasPrice":"0x5d21dba000","to":"0x57f18debc2ec90e757616ccc279e43828dbb17ea","data":"60fe47b10000000000000000000000000000000000000000000000000000000000000002"}]}' 'localhost:23890'

type Payload struct {
	ID      string   `json:"id"`
	Jsonrpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []Params `json:"params"`
}
type Params struct {
	From     string `json:"from"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	To       string `json:"to"`
	Data     string `json:"data"`
}
type Resp struct {
	ID      string   `json:"id"`
	Jsonrpc string   `json:"jsonrpc"`
	Result  string   `json:"result"`
}

func (c *Connection) Send(params []byte) (ethcommon.Hash, error) {
	data := Payload{
		ID: "1",
		Jsonrpc: "2.0",
		Method: "eth_sendTransaction",
		Params: []Params{
			{
				From: c.fromAddress,
				Gas: "0x6691b7",
				GasPrice: "0x5d21dba000",
				To: c.bridgeAddress.String(),
				Data: ethcommon.Bytes2Hex(params),
			},
		},
	}

	fmt.Printf("send data: %+v", data) // todo to be removed

	payloadBytes, err := json.Marshal(data)
	if err != nil {
		c.log.Error("json.Marshal error", err)
		return ethcommon.Hash{}, err
	}
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", c.endpoint, body)
	if err != nil {
		c.log.Error("NewRequest error", err)
		return ethcommon.Hash{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.log.Error("DefaultClient.Do error", err)
		return ethcommon.Hash{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var buf bytes.Buffer
		var body []byte
		if _, err := buf.ReadFrom(resp.Body); err == nil {
			body = buf.Bytes()
		}
		errmsg := fmt.Sprintf("status: %s, statusCode: %d", resp.Status, resp.StatusCode)
		c.log.Error("DefaultClient.Do error", errmsg, body)
		return ethcommon.Hash{}, errors.New(errmsg)
	}

	defer resp.Body.Close()

	respmsg := &Resp{}
	err = json.NewDecoder(resp.Body).Decode(respmsg)
	if err != nil {
		c.log.Error("json.Unmarshal(respbody, respdata) error", err)
		return ethcommon.Hash{}, err
	}

	return ethcommon.HexToHash(respmsg.Result), nil
}

