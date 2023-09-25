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
- Execute the following command to initiate the service:
    ```
    ./build_and_setup.sh
    ```
