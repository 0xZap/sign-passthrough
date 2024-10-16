#!/usr/bin/env bats

PUBLIC_KEY_PATH="certs/rsa_public_key.pem"

verify_signature() {
    local body="$1"
    local signature_base64="$2"
    local public_key="$3"

    echo "Debug - Body hex dump:" >&3
    echo -n "$body" | xxd >&3

    echo "Debug - Signature (base64):" >&3
    echo "$signature_base64" >&3

    echo "Debug - Decoded signature hex:" >&3
    echo "$signature_base64" | base64 -d | xxd >&3

    body_file=$(mktemp)
    echo -n "$body" > "$body_file"

    echo "Debug - Body file hex dump:" >&3
    xxd "$body_file" >&3

    signature_file=$(mktemp)
    echo "$signature_base64" | base64 -d > "$signature_file"

    echo "Debug - Body file size: $(wc -c < "$body_file")" >&3
    echo "Debug - Signature file size: $(wc -c < "$signature_file")" >&3

    echo "Debug - OpenSSL verification:" >&3
    openssl dgst -sha256 -verify "$public_key" -signature "$signature_file" "$body_file" 2>&1
    local result=$?

    rm -f "$body_file" "$signature_file"

    return $result
}

@test "API response returns valid JSON and signature is correct" {
    response=$(curl -k -i https://localhost/api/data)

    echo "Debug - Complete raw response:" >&3
    echo "$response" | xxd >&3

    headers=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"} {print $0; exit}')
    body=$(echo "$response" | awk 'BEGIN{RS="\r\n\r\n"} NR==2 {print $0}' | tr -d '\r\n')

    signature=$(echo "$headers" | grep -i "X-Signed-Checksum:" | cut -d':' -f2- | tr -d ' \r\n')

    echo "Debug - Extracted headers:" >&3
    echo "$headers" | xxd >&3
    echo "Debug - Extracted body:" >&3
    echo "$body" | xxd >&3
    echo "Debug - Extracted signature: $signature" >&3

    [ -n "$signature" ]

    echo "$body" | jq . >/dev/null
    [ "$?" -eq 0 ]

    echo "Debug - Formatted JSON:" >&3
    echo "$body" | jq . >&3

    run verify_signature "$body" "$signature" "$PUBLIC_KEY_PATH"
    [ "$?" -eq 0 ]
}