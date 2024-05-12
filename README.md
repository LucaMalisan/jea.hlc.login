# jea.hlc.login

How to setup:
1. Install OpenSSL
2. Generate a pair of a private and a public key and store them in your project
3. Add the path to application.properties (replace the values with yours):

```
rsa.private-key=classpath:certs/private.pem
rsa.public-key=classpath:certs/public.pem
```
   
4. Register the login application at Auth0 and add these properties to application.properties (replace the values with yours)

```
security.oauth2.client.id=id
security.oauth2.client.secret=secret
security.oauth2.audience=https://dev-rqhpuzb3altnalx3.us.auth0.com/api/v2/ 
security.oauth2.url=https://dev-rqhpuzb3altnalx3.us.auth0.com/oauth/token 
   ```

