## Prerequisite
-  Generate self-signed certificate
    ```
    mkdir ssl
    # interactive
    openssl req -x509 -newkey rsa:4096 -keyout ssl/private.key -out ssl/certificate.crt -sha256 -days 365
    # non-interactive
    openssl req -x509 -newkey rsa:4096 -keyout ssl/private.key -out ssl/certificate.crt -sha256 -days 365 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
    ```
## Run
1. Run docker containers
    ```
    docker compose up -d
    ```
2.  Initialize database
    ```
    docker exec fastapi_rbac-fastapi-1 python3 setup.py
    ```