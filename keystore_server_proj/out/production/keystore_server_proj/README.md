# Keystore Server Project
This project contains the SSL server implementation using Java keystore.

I genereated a self-signed certificate and created a keystore using the following command:

```bash
keytool -genkeypair -alias server -keyalg RSA -keystore server.keystore -storepass password123 -validity 365 -keysize 2048 -dname "CN=localhost"
Generating 2048 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 365 days
for: CN=localhost
```


I then exported the certificate from the keystore using the following command:
This is server certificate: 
```bash
keytool -exportcert -alias server -keystore server.keystore -file server.cer -storepass password123
Certificate stored in file <server.cer>
```

Then I created a truststore and imported the server certificate into the truststore using the following command:
```bash
keytool -importcert -alias server -file server.cer -keystore client.truststore -storepass password123 -noprompt
Certificate was added to keystore
client.truststore created successfully.
```
