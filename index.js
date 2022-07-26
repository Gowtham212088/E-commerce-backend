import express, { response, text } from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
// import nodemailer from "nodemailer";
import { request } from "http";
import jsonwebtocken from "jsonwebtoken";
import { verify } from "crypto";

const app = express();

//! Express MiddleWare (Body Parser) 
app.use(express.json())

//! Configuring Enviroinment variables
dotenv.config()

//! Cors (Third party middleware)
app.use(cors()) 


const PORT = 5000;

const MONGO_URL = process.env.MONGO_URL;

const client = await createConnection()

app.get("/",async(request,response)=>{
    response.send("Welcome to E-commerce app")
})

app.listen(PORT,()=>console.log(`Server connected on port ${PORT} 😊😊`))


//! DataBase Connection

async function createConnection() {
    const client = new MongoClient(MONGO_URL);
  
    await client.connect();
  
    console.log("MongoDB is connected to Server 😎😍");
  
    return client;
  };