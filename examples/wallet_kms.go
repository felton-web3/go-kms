package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/keithballdotnet/go-kms/kms"
)

// WalletKey 表示一个钱包密钥
type WalletKey struct {
	KeyID     string `json:"keyId"`
	Address   string `json:"address"`
	Encrypted []byte `json:"encrypted"`
}

// WalletManager 管理钱包密钥
type WalletManager struct {
	kmsProvider kms.CryptoProvider
	keys        []WalletKey
	keyStore    string
}

// NewWalletManager 创建一个新的钱包管理器
func NewWalletManager(kmsProvider kms.CryptoProvider, keyStore string) *WalletManager {
	return &WalletManager{
		kmsProvider: kmsProvider,
		keyStore:    keyStore,
		keys:        make([]WalletKey, 0),
	}
}

// GenerateWallets 生成指定数量的钱包
func (wm *WalletManager) GenerateWallets(count int) error {
	// 创建 KMS 密钥
	keyMetadata, err := wm.kmsProvider.CreateKey("Wallet encryption key")
	if err != nil {
		return fmt.Errorf("创建 KMS 密钥失败: %v", err)
	}

	// 生成钱包
	for i := 0; i < count; i++ {
		// 生成私钥
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("生成私钥失败: %v", err)
		}

		// 获取地址
		address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

		// 序列化私钥
		privateKeyBytes := crypto.FromECDSA(privateKey)

		// 加密私钥
		encryptedKey, err := wm.kmsProvider.Encrypt(privateKeyBytes, keyMetadata.KeyID)
		if err != nil {
			return fmt.Errorf("加密私钥失败: %v", err)
		}

		// 创建钱包密钥记录
		walletKey := WalletKey{
			KeyID:     keyMetadata.KeyID,
			Address:   address,
			Encrypted: encryptedKey,
		}

		wm.keys = append(wm.keys, walletKey)
	}

	// 保存钱包信息
	return wm.saveWallets()
}

// saveWallets 保存钱包信息到文件
func (wm *WalletManager) saveWallets() error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(wm.keyStore), 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}
	data, err := json.MarshalIndent(wm.keys, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化钱包数据失败: %v", err)
	}

	return os.WriteFile(wm.keyStore, data, 0600)
}

// loadWallets 从文件加载钱包信息
func (wm *WalletManager) loadWallets() error {
	data, err := os.ReadFile(wm.keyStore)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取钱包数据失败: %v", err)
	}

	return json.Unmarshal(data, &wm.keys)
}

// GetPrivateKey 通过地址获取私钥
func (wm *WalletManager) GetPrivateKey(address string) (*ecdsa.PrivateKey, error) {
	// 查找对应的钱包
	var walletKey *WalletKey
	for _, k := range wm.keys {
		if k.Address == address {
			walletKey = &k
			break
		}
	}

	if walletKey == nil {
		return nil, fmt.Errorf("未找到地址 %s 对应的钱包", address)
	}

	// 解密私钥
	decryptedData, _, err := wm.kmsProvider.Decrypt(walletKey.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %v", err)
	}

	// 转换为私钥对象
	privateKey, err := crypto.ToECDSA(decryptedData)
	if err != nil {
		return nil, fmt.Errorf("转换私钥失败: %v", err)
	}

	return privateKey, nil
}

func main() {
	// 设置主密钥口令
	os.Setenv("GOKMS_KSMC_PASSPHRASE", "A long passphrase that will be used to generate the master key")

	// 初始化 KMS 配置
	kms.InitConfig()
	provider, err := kms.NewKMSCryptoProvider()
	if err != nil {
		log.Fatalf("KMS 初始化失败: %v", err)
	}

	// 创建钱包管理器
	keyStore := filepath.Join("data", "wallets.json")
	walletManager := NewWalletManager(provider, keyStore)

	// 生成 10000 个钱包
	fmt.Println("开始生成钱包...")
	err = walletManager.GenerateWallets(10000)
	if err != nil {
		log.Fatalf("生成钱包失败: %v", err)
	}
	fmt.Println("钱包生成完成！")

	// 示例：获取第一个钱包的私钥
	if len(walletManager.keys) > 0 {
		address := walletManager.keys[0].Address
		privateKey, err := walletManager.GetPrivateKey(address)
		if err != nil {
			log.Fatalf("获取私钥失败: %v", err)
		}
		fmt.Printf("成功获取地址 %s 的私钥\n", address)
		fmt.Printf("私钥: %x\n", crypto.FromECDSA(privateKey))
	}
}
