#!/usr/bin/env bats

PUBLIC_KEY_PATH="certs/rsa_public_key.pem"

verify_signature() {
  local data="$1"
  local signature="$2"

  local signature_binary=$(echo "$signature" | xxd -r -p)

  echo "Response body length: ${#data}"
  echo "Signature length (binary): ${#signature_binary}"

  echo -n "$data" | openssl dgst -sha256 -verify "$PUBLIC_KEY_PATH" -signature <(echo -n "$signature_binary")
}

@test "API response contains signed checksum header" {
    result=$(curl -k -I https://localhost/api/data)
    checksum=$(echo "$result" | grep -i "X-Signed-Checksum" | awk '{print $2}' | tr -d '\r\n')

    [ -n "$checksum" ]
}

@test "API response returns valid JSON and signature is correct" {
    result=$(curl -k https://localhost/api/data)
    headers=$(curl -k -I https://localhost/api/data)
    checksum=$(echo "$headers" | grep -i "X-Signed-Checksum" | awk '{print $2}' | tr -d '\r\n')

    [[ "$result" =~ "This is a test API response" ]]

    echo "X-Signed-Checksum: $checksum"

    verify_signature "$result" "$checksum"

    [ $? -eq 0 ]
}
