import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { BASE_URL, MONGO_URI } from "./vite.setup.js";
import express from  'express';
import { runMongoDB } from "../src/db/runMongoDB.js";
import { User } from "../src/models/v1/users.model.js";
import mongoose from "mongoose";
import { enable2FA, login, logout, register, resetPassword } from "../src/controllers/v1/auth.controller.js";
import { errorHandler } from "../src/middlewares/errorHandler.middleware.js";
import { rateLimiter } from "../src/middlewares/rateLimiter.middleware.js";
import { RateLimiterMemory } from "rate-limiter-flexible";
import { createLimiter } from "../src/utils/createLimiter.js";
import { verifyToken } from "../src/middlewares/verifyToken.middleware.js";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import dotenv from 'dotenv';
import { verify2FA } from "../src/middlewares/verify2FA.middleware.js";
import speakeasy from 'speakeasy';
import { decryptSec } from "../src/utils/decryptSec.js";

dotenv.config();

const REQ_LIMIT = 5;
const DURATION = 10;
const EMAIL = 'testingauthrouter@email.com';
const PASSWORD = 'HelloKitty@9';

const mainOpts = {
  method: 'POST',
  headers:  { 'Content-Type': 'application/json'},
  body: JSON.stringify({ 
    email: EMAIL, 
    password: PASSWORD 
  })
};

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

let server;

describe('Auth Router - Register', () => {
  const route = '/register';
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    await User.deleteOne({ email: EMAIL });
    app.post(route, rateLimiter(
      createLimiter({
        points: REQ_LIMIT,
        duration: DURATION
      }, RateLimiterMemory)), register);
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should create user and return 201', async () => {
    const response = await fetch(BASE_URL + route, mainOpts);
    expect(response.status).toBe(201);
  });
});

describe('Auth Router - Login & Rate Limiting', () => {
  const route = '/login';
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    app.post(route, rateLimiter(
      createLimiter({
        points: REQ_LIMIT,
        duration: DURATION
      }, RateLimiterMemory)), login);
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should return 200 for valid login and 429 for exceeding the limit', async () => {
    let response;
    for(let i = 0; i < REQ_LIMIT; i++) {
      response = await fetch(BASE_URL + route, mainOpts);
      expect(response.status).toBe(200);
    }
    response = await fetch(BASE_URL + route, mainOpts);
    expect(response.status).toBe(429);
  });
});

describe('Token Verification - Valid Token', () => {
  const route = '/protected-1';
  let token;
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    const user = await User.findOne({ email: EMAIL });
    token = user.token;
    app.post(route, verifyToken, (req, res, next) => {
      return res.status(200).json({ userId: req.userId });
    });
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should return 200 and user data when accessing a protected route with a valid token.', async () => {
    const response = await fetch(BASE_URL + route, { 
      method: 'POST',
      credentials: 'include',
      headers: { Cookie: `token=${token}`}
    });
    const { userId } = await response.json();
    expect(response.status).toBe(200);
    expect(userId).toBeDefined();
  });
});

describe('Auth Router - Logout', async () => {
  const route = '/logout';
  let token;
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    const user = await User.findOne({ email: EMAIL });
    token = user.token;
    app.post(route, rateLimiter(
      createLimiter({
        points: REQ_LIMIT,
        duration: DURATION
      }, RateLimiterMemory)), logout);
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should delete user token and return 200', async () => {
    const response = await fetch(BASE_URL + route, { 
      method: 'POST',
      credentials: 'include',
      headers: {
        Cookie: `token=${token}`
      },
    });
    expect(response.status).toBe(200);
  });
});

describe('Token Verification - Invalid Token', () => {
  const route = '/protected-1';
  let token;
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    const user = await User.findOne({ email: EMAIL });
    token = user.token;
    app.post(route, verifyToken, (req, res, next) => {
      return res.status(200).json({ userId: req.userId });
    });
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should return 400 and undefined user data when accessing a protected route with an invalid token.', async () => {
    const response = await fetch(BASE_URL + route, { 
      method: 'POST',
      credentials: 'include',
      headers: { Cookie: `token=${token}`}
    });
    const { userId } = await response.json();
    expect(response.status).toBe(400);
    expect(userId).toBeUndefined();
  });
});

describe('Auth Router - Enable 2FA', () => {
  const route = '/enable-2FA';
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    app.post(route, rateLimiter(
      createLimiter({
        points: REQ_LIMIT,
        duration: DURATION
      }, RateLimiterMemory)), enable2FA);
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should return 200 and a QR code on 2FA enable', async () => {
    const response = await fetch(BASE_URL + route, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL })
    });
    const { qrCode } = await response.json();
    expect(response.status).toBe(200);
    expect(qrCode).toBeDefined();
  });
});

describe('Verification - 2FA Valid OTP', () => {
  const route = '/protected-2';
  let secret; 
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    const user = await User.findOne({ email: EMAIL });
    const decrypted = decryptSec(user.twoFAsecret);
    secret = decrypted;
    app.post(route, verify2FA, (req, res, next) => {
      return res.status(200).json({ userId: req.userId });
    });
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  it('should return 200 and user data when accessing a protected route with a valid OTP.', async () => {
    const otp = speakeasy.totp({ 
      secret: secret, 
      encoding: 'base32'
    });
    const validRes = await fetch(BASE_URL + route, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, otp: otp })
    });
    const valdiData = await validRes.json();
    expect(validRes.status).toBe(200);
    expect(valdiData.userId).toBeDefined();
    const invalidRes = await fetch(BASE_URL + route, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: EMAIL, otp: '123456' })
    });
    const invaldiData = await invalidRes.json();
    expect(invalidRes.status).toBe(400);
    expect(invaldiData.userId).toBeUndefined();
  });
});

describe('Auth Router - Reset Password', () => {
  const route = '/reset-password';
  beforeAll(async () => {
    await runMongoDB(MONGO_URI);
    app.post(route, rateLimiter(
      createLimiter({
        points: REQ_LIMIT,
        duration: DURATION
      }, RateLimiterMemory)), resetPassword);
    app.use(errorHandler);
    server = app.listen(5000);
  });
  afterAll(async () => {
    await mongoose.connection.close();
    await server.close();
  });
  const newPassword = 'runningTest@0937';
  it('should reset password and return 200', async () => {
    const response = await fetch(BASE_URL + route, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: EMAIL, 
        newPass: newPassword, 
        confirmPass: newPassword 
      })
    });
    expect(response.status).toBe(200);
  });
});






