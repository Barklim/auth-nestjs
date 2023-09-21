[link](https://coursehunter.net/course/nestjs-autentifikaciya-i-avtorizaciya)

## install

```
nest new
	auth-nestjs
```

```
nest g resource coffees
nest g resource users
	rest api
```

npm run start:dev

docker-compose up -d

npm i @nestjs/typeorm typeorm pg


## bcrypt

npm i bcrypt
npm i @types/bcrypt -D

```
nest g module iam
nest g service iam/hashing
nest g service iam/hashing/bcrypt --flat
```


## sign in sign up routes

```
nest g controller iam/authentication
nest g service iam/authentication
nest g class iam/authentication/dto/sign-in.dto --no-spec
nest g class iam/authentication/dto/sign-up.dto --no-spec
```

```
npm i class-validator class-transformer
```

```
POST http://localhost:3000/authentication/sign-in
{
	"email": "user1@nestjs.com",
	"password": "Password!123"
}
POST localhost:3000/authentication/sign-up
```


## jwt

```
npm i @nestjs/jwt @nestjs/config
```

.env
```
# JWT
JWT_SECRET=YOUR_SECRET_KEY_HERE
JWT_TOKEN_AUDIENCE=localhost:3000
JWT_TOKEN_ISSUER=localhost:3000
JWT_ACCESS_TOKEN_TTL=3600
JWT_REFRESH_TOKEN_TTL=86400

# TFA
TFA_APP_NAME=auth-playground

# Google
GOOGLE_CLIENT_ID=YOUR_ID_NAME
GOOGLE_CLIENT_SECRET=YOUR_SECRET_HERE

# Sessions
SESSION_SECRET=YOUR_SESSION_SECRET_HERE
```

POST localhost:3000/authentication/sign-in

POST localhost:3000/authentication/sign-in
(cookies)


## protecting routes by guard

```
nest g guard iam/authentication/guards/access-token
```

```
GET http://localhost:3000/coffees
Authorization: Bearer ...
```


## public route

```
nest g guard iam/authentication/guards/authentication
```


## active user decorator


## implement refresh tokens

```
.env
JWT_REFRESH_TOKEN_TTL=86400
```

```
POST localhost:3000/authentication/refresh-tokens
{
	"refreshToken": "asdfk"
}
```


## invalidating tokens

```
nest g class iam/authentication/refresh-token-ids.storage
```

```
POST localhost:3000/authentication/sign-in
get generated refresh token
POST localhost:3000/authentication/refresh-tokens
```


## Role-Based Access Control

```
npm run start -- --entryFile repl
```

```
await get("UserRepository").update({ id: 1 }, { role: 'regular' })
await get("UserRepository").find()
```

```
nest g guard iam/authorization/guards/roles
POST localhost:3000/coffees
```

```
await get("UserRepository").update({ id: 1 }, { role: 'admin' })
```


## Claims based auth

```
POST localhost:3000/authentication/sign-in
POST localhost:3000/coffees
```
npm run start -- --entryFile repl

await get("UserRepository").update({ id: 1 }, { permissions: ['create_coffee'] })


## policy-based auth


## integrate api keys feature

```
nest g class users/api-keys/entities/api-key.entity --no-spec
nest g service iam/authentication/api-key --flat
nest g guard iam/authentication/guards/api-key
```

```
npm run start -- --entryFile repl
uuid = 'random_unique_id'
payload = await get(ApiKeysService).createAndHash(uuid)
await get("ApiKeyRepository").save({ uuid, key: payload.hashedKey, user: { id: 1 }})
ApiKey cmFuZG9tX3VuaXF1ZV9pZCA4OTZmZmVmNC1jYjIzLTQwOGUtYTVkNS1kZTI5YTAwODE1MzQ=
await get("UserRepository").find()
```

## google oauth

```
npm i google-auth-library
nest g s iam/authentication/social/google-authentication --flat
nest g co iam/authentication/social/google-authentication --flat
```


## two factor authentication

```
npm i otplib qrcode
npm i -D @types/qrcode
nest g service iam/authentication/opt-authentication
```


## sessions with passport

```
npm i passport @nestjs/passport express-session
npm i -D @types/passport @types/express-session
nest g service iam/authentication/session-authentication --flat
nest g controller iam/authentication/session-authentication --flat
nest g class iam/authentication/serializers/user-serializer --flat
nest g guard iam/authentication/guards/session

npm i connect-redis
npm i -D @types/connect-redis
```