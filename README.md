# NGINX Sign Passthrough Module

A custom NGINX module that allows developers to easily sign the body of API responses using cryptographic keys. The objective is to add an extra layer of security to API responses by enabling verification of the integrity and authenticity of the data returned to clients, encouraging the use of digital signatures for zero-knowledge (zk) proof of data integrity.

## Features

-   **Response Signing:** Sign the body of API responses using cryptographic keys.
-   **Easy Integration:** Minimal configuration required to enable response signing in NGINX.
-   **Open-source:** The project is open-source and customizable to suit specific requirements, so it can serve as a base for your own projects and be extended as needed.

## Getting Started

To get started with the module, follow the instructions below.

### Setup Instructions

#### 1. Build the Custom NGINX Module

The first step is to build the custom NGINX module using the `Dockerfile.module`, which will generate the `.so` file required for the module.

To build the module, run the following command:

```bash
docker build -f Dockerfile.module -t nginx-sign-module-builder .
```

This will generate the `.so` file for the custom NGINX module and store it in a Docker volume named `modules-volume`.

#### 2. Extract the `.so` Module

After building the module, extract the generated `.so` file from the Docker volume to your local system:

```bash
docker run --rm -v $(pwd):/output nginx-sign-module-builder cp /sign-module/ngx_http_sign_module.so /output/
```

This will copy the `ngx_http_sign_module.so` file to your current directory, so you can use it to configure NGINX.

#### 3. Configure NGINX with the Module

1.  Copy the `ngx_http_sign_module.so` file to your NGINX server's module directory (e.g., `/usr/lib/nginx/modules/`).
2.  Modify your NGINX configuration (`nginx.conf`) to load the custom module. Add the following line:

    ```nginx
    load_module modules/ngx_http_sign_module.so;
    ```

    Below is an example snippet from the `nginx.conf` for using the module:

    ```nginx
    http {
    	server {
    		listen 443 ssl;
    		server_name localhost;

    		ssl_certificate     /path/to/nginx-selfsigned.crt;
    		ssl_certificate_key /path/to/nginx-selfsigned.key;

    		location / {
    			sign_passthrough /path/to/rsa_private_key.pem;
    			proxy_pass http://server:5000;
    		}
    	}
    }
    ```

3.  Ensure that the NGINX service is restarted after the configuration update:

    ```bash
    sudo systemctl restart nginx
    ```

### Running the Example Setup (Local Testing)

The project includes an example setup with a Flask server, which demonstrates the module in action, provided on [e2e](e2e) directory.

To run the example:

```bash
cd e2e
docker-compose up --build
```

This will start both the NGINX server (with the custom signing module) and the Flask server for API testing.

### Testing the Module

The project also includes end-to-end tests to verify that the response signing is functioning as expected.

To run the tests, you can use the [BATS testing framework](https://github.com/bats-core/bats-core):

```bash
bats tests
```

This will execute the tests, validating that the NGINX module correctly signs responses.
