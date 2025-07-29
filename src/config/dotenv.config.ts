import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const DotenvConfig = {
  serverPort: process.env.PORT as unknown as number,
  Database: {
    url: process.env.MONGO_URL as string,
    testUrl: process.env.TEST_MONGO_URL as string,
  },
  JWTHeader: {
    issuer: process.env.JWT_ISSUER as string,
    audience: process.env.JWT_AUDIENCE as string,
    algorithm: process.env.JWT_ALGORITHM as unknown as jwt.Algorithm,
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET as string,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET as string,
  },
  TokenExpiry: {
    accessToken: parseInt(process.env.ACCESS_TOKEN_EXPIRY as string),
    refreshToken: parseInt(process.env.REFRESH_TOKEN_EXPIRY as string),
    rememberMe: parseInt(process.env.REMEMBER_ME_EXPIRY as string),
  },
  SMTP: {
    user: process.env.SMTP_USER as string,
    password: process.env.SMTP_PASSWORD as string,
    service: process.env.SMTP_SERVICE as string,
    port: process.env.SMTP_PORT as string,
    secure: process.env.MAIL_SECURE as unknown as boolean,
  },
  Google: {
    clientID: process.env.GOOGLE_AUTH_CLIENT_ID as string,
    clientSecret: process.env.GOOGLE_AUTH_CLIENT_SECRET as string,
    callbackUrl: process.env.GOOGLE_AUTH_CALLBACK_URL as string,
    successUrl: process.env.GOOGLE_AUTH_SUCCESS_REDIRECT_URL as string,
    failureUrl: process.env.FAILURE_REDIRECT_URL as string,
  },
  Cloud: {
    folder: process.env.CLOUDINARY_FOLDER as string,
    name: process.env.CLOUDINARY_CLOUD_NAME as string,
    secret: process.env.CLOUDINARY_SECRET_KEY as string,
    key: process.env.CLOUDINARY_API_KEY as string,
  },
  Cors: {
    origin: process.env.CORS_ORIGIN as string,
    methods: process.env.CORS_METHODS as string,
    allowedHeaders: process.env.CORS_ALLOWED_HEADERS as string,
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },
  serverBaseURL: process.env.SERVER_BASE_URL as string,
  frontendBaseURL: process.env.FRONTEND_BASE_URL as string,
  BcryptSalt: parseInt(process.env.BCRYPT_SALT as string),
  CompanyName: process.env.COMPANY_NAME as string,
};

export default DotenvConfig;
