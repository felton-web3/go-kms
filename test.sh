#!/bin/bash

# 设置变量
AUTH_KEY=$(cat files/auth.key)
BASE_URL="https://localhost:8011"
DATE=$(date -u +'%a, %d %b %Y %H:%M:%S GMT')

# 生成认证头
generate_auth_header() {
    local method=$1
    local resource=$2
    local message="${method}\n${DATE}\n${resource}"
    local hmac=$(python3 -c "import sys,hmac,hashlib,base64;print(base64.b64encode(hmac.new(open('files/auth.key','rb').read(), b'${message}', hashlib.sha256).digest()).decode())")
    echo "Authorization: ${hmac}"
}

# 1. 创建密钥
echo "测试创建密钥..."
CREATE_KEY_RESP=$(curl -sk -X POST \
  -H "$(generate_auth_header 'POST' '/api/v1/go-kms/createkey')" \
  -H "x-kms-date: ${DATE}" \
  -H "Content-Type: application/json" \
  -d '{"Description": "自动化测试密钥"}' \
  "${BASE_URL}/api/v1/go-kms/createkey")
echo "创建密钥响应: $CREATE_KEY_RESP"
KEY_ID=$(echo "$CREATE_KEY_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin)['KeyMetadata']['KeyId'])")
echo "提取到的KeyId: $KEY_ID"

# 2. 列出密钥
echo -e "\n\n测试列出密钥..."
LIST_KEYS_RESP=$(curl -sk -X POST \
  -H "$(generate_auth_header 'POST' '/api/v1/go-kms/listkeys')" \
  -H "x-kms-date: ${DATE}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${BASE_URL}/api/v1/go-kms/listkeys")
echo "列出密钥响应: $LIST_KEYS_RESP"

# 3. 加密数据
echo -e "\n\n测试加密数据..."
ENCRYPT_RESP=$(curl -sk -X POST \
  -H "$(generate_auth_header 'POST' '/api/v1/go-kms/encrypt')" \
  -H "x-kms-date: ${DATE}" \
  -H "Content-Type: application/json" \
  -d '{"KeyID": "'$KEY_ID'", "Plaintext": "SGVsbG8gV29ybGQ="}' \
  "${BASE_URL}/api/v1/go-kms/encrypt")
echo "加密响应: $ENCRYPT_RESP"
CIPHERTEXT=$(echo "$ENCRYPT_RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d['CiphertextBlob']) if 'CiphertextBlob' in d else print('')")
echo "加密后的密文: $CIPHERTEXT"

# 4. 解密数据
echo -e "\n\n测试解密数据..."
DECRYPT_RESP=$(curl -sk -X POST \
  -H "$(generate_auth_header 'POST' '/api/v1/go-kms/decrypt')" \
  -H "x-kms-date: ${DATE}" \
  -H "Content-Type: application/json" \
  -d '{"KeyID": "'$KEY_ID'", "CiphertextBlob": "'$CIPHERTEXT'"}' \
  "${BASE_URL}/api/v1/go-kms/decrypt")
echo "解密响应: $DECRYPT_RESP"
PLAINTEXT=$(echo "$DECRYPT_RESP" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d['Plaintext']) if 'Plaintext' in d else print('')")
echo "解密后的明文: $PLAINTEXT"

# 5. 禁用密钥
echo -e "\n\n测试禁用密钥..."
DISABLE_KEY_RESP=$(curl -sk -X POST \
  -H "$(generate_auth_header 'POST' '/api/v1/go-kms/disablekey')" \
  -H "x-kms-date: ${DATE}" \
  -H "Content-Type: application/json" \
  -d '{"KeyID": "'$KEY_ID'"}' \
  "${BASE_URL}/api/v1/go-kms/disablekey")
echo "禁用密钥响应: $DISABLE_KEY_RESP" 