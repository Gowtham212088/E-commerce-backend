import express, { response } from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import jsonwebtocken from "jsonwebtoken";
import { request } from "http";

const app = express();

//! Express MiddleWare (Body Parser)
app.use(express.json());

const auth_Admin = (request, response, next) => {
 
  const token = request.header("x-auth-token");
  
 const verifyToken = jsonwebtocken.verify(token, process.env.privateKey1);
 if(verifyToken.role === "Admin"){
  next();
 }else{
  response.status(401).send({ error: err.message });
 }
};

//! Custom Middleware for Admin session

const auth_vendor = (request, response, next) => {
 
    const token = request.header("x-auth-token");
    
   const verifyToken = jsonwebtocken.verify(token, process.env.privateKey1);
   if(verifyToken.role === "vendor"){
    next();
   }else{
    response.status(401).send({ error: err.message });
   }
  };

  
//! Configuring Enviroinment variables
dotenv.config();

//! Cors (Third party middleware)
app.use(cors());

const PORT = process.env.PORT || 5000;

const MONGO_URL = process.env.MONGO_URL;

const client = await createConnection();

//! App Welcome Message

app.get("/", (request, response) => {
  response.send("Welcome to Ecommerce App");
});

// ?  SIGNUP DETAILS

app.post("/create/users", auth_Admin,async (request, response) => {
  const { name, email, password, role, district, userDp, product } = request.body;

  // !  PASSWORD HASHING PROCESS 
 //? ADMIN ONLY

  const hashPassword = await createPassword(password);

  const newUser = {
    name: name,
    email: email,
    password: hashPassword,
    role: role,
    district: district,
    userDp: userDp,
  };

  const checkExisting = await client
    .db("ecommerce")
    .collection("user")
    .findOne({ email: newUser.email });

  if (!checkExisting) {
    const signUp = await client
      .db("ecommerce")
      .collection("user")
      .insertOne(newUser);

    if (!signUp) {
      response.status(404).send("Error");
    } else {
      response.send("User Created Sucessfully");
    }
  } else {
    response.status(409).send("Account already exists");
  }
});

//! Get all unique products by Id (Product Info).
app.get('/products/customers/:id',async(request,response)=>{

  const {id} = request.params;

const getAllData = await client.db("ecommerce").collection("products").find().toArray()

const filterApproved = getAllData.filter((element)=>{
  return element.Approvel === true
})

response.send(filterApproved[id])

})

//! Get all approved products.
app.get('/products/customers',async(request,response)=>{

const getAllData = await client.db("ecommerce").collection("products").find().toArray()

const filterApproved = getAllData.filter((element)=>{
  return element.Approvel === true
})

response.send(filterApproved)

})

//!  LOGIN VERIFICATION
//?  BOTH A SELLER AND ADMIN
app.post("/user/signIn",async (request, response) => {

  const { email, password, _id } = request.body;

  const signIn = await client
    .db("ecommerce")
    .collection("user")
    .findOne({ email: email });

  if (!signIn) {
    response.status(401).send("Invalid Credentials");
  } else {
    const storedPassword = signIn.password;
    const isPasswordMatch = await bcrypt.compare(password, storedPassword);
    if (!isPasswordMatch) {
      response.status(401).send("Invalid credentials");
    } else {
      const token = jsonwebtocken.sign(
        {
          _id: signIn._id,
          name:signIn.name,
          email: signIn.email,
          role:signIn.role,
          district:signIn.district,
          picture:signIn.userDp,
          product:signIn.product
        },
        process.env.privateKey1
      );
      response.send({ message: `Welcome ${signIn.name}`, token: token });
    }
  }
});

//? FOR BOTH A SELLER & ADMIN 

app.post("/conform/mailVerification", async (request, response) => {
   const data = request.body;

  const { name, email } = request.body;

  let token = await tokenGenerator(email);
  
  const verifyIt = await jsonwebtocken.verify(token, process.env.privateKey3);

  // ? Here we check wheather the mentioned email-id in forgot-password page available in DB or Not.

  // ? If email exists in DB we send mail to the existing mail-id.

  const checkAvailablity = await client
    .db("signUp")
    .collection("user")
    .findOne(data);

  const BSON_id = await checkAvailablity._id;

  if (!checkAvailablity) {
    response.status(404).send("User doesn't exist");
  } else {
    // ?  Node Mailer

    var sender = nodemailer.createTransport({
      service: "gmail", // Service Provider
      // Authentication
      auth: {
        user: process.env.secondaryMail, // Email
        pass: process.env.secondaryPass, // Password
      },
    });

    var composemail = {
      from: process.env.secondaryMail, // Sender address
      to: email,
      subject: "Password verification",
      text: `${process.env.Base_URL}/${BSON_id}/${token}`,
    };
    
    sender.sendMail(composemail).then((response,request)=>{
     response.send({
        to: email,
        subject: subject,
        message:
          "Please Click the link below to reset the passsword for security reasons the link will be expired in the next 10 minute",
      });
      
 }).catch((error)=>{
      response.send(error)
    })
  }})

//?  BOTH A SELLER & ADMIN

app.post("/new-password/:_id/:token", async (request, response) => {

  const { _id } = request.params;

  const { token } = request.params;

  const { password, newPassword } = request.body;

  const conformId = await client
    .db("signUp")
    .collection("user")
    .findOne({ _id: ObjectId(`${_id}`) });
  // console.log(conformId.email);
  if (!conformId) {
    response.status(404).send("not found");
  } else {
    const verify = await jsonwebtocken.decode(token, process.env.privateKey3);
    // console.log(verify.email);

    //? CONFORMING E-MAIL FROM TOKEN AND DATABASE

    if (verify.email !== conformId.email) {
      response.status(404).send("Token not Matched");
    } else {
      if (password == newPassword) {
        const updatedHashPassword = await createPassword(password);

        const updatePassword = await client
          .db("signUp")
          .collection("user")
          .updateOne(
            { _id: ObjectId(`${_id}`) },
            { $set: { password: updatedHashPassword } }
          );

        response.send("Password updated Successfully");
      } else {
        response.send("Password Mismatches");
      }
    }
  }
});

//// TESTED OK (SELLER LOGIN)
//! For getting user profile data.
//? For Seller.

app.get("/get/userData", auth_vendor, async (request, response) => {
  const getDatas = request.header("x-auth-token");

  const crackData = jsonwebtocken.verify(getDatas, process.env.privateKey1);

  const getId = crackData._id;

  console.log(getId);

  const data = await client.db("ecommerce").collection("user").findOne({ _id: ObjectId(`${getId}`) })

  response.send(data);

});

//// TESTED OK (WITH ADMIN LOGIN)
//! Admin's information only.
//? Admin Only.

app.get("/get/adminData", auth_Admin, async (request, response) => {

  const getDatas = request.header("x-auth-token");

  const crackData = jsonwebtocken.verify(getDatas, process.env.privateKey1);

  const getId = crackData._id;

  const data = await client.db("ecommerce").collection("user").findOne({ _id: ObjectId(`${getId}`) })

  response.send(data);

});

//! Get all products for approval purposes.
// ? Admin only

app.get('/get/allProducts',auth_Admin,async(request,response)=>{

  const getDatas = request.header("x-auth-token");

  const crackData = jsonwebtocken.verify(getDatas, process.env.privateKey1);

if(crackData.role === 'Admin'){

  const data = await client.db("ecommerce").collection("products").find().toArray()

}
 response.send(crackData)
})




//// TESTED OK WITH (ADMIN LOGIN)
//! Users informations for Admin.
//? Admin Only.

app.get("/get/allUsersData", auth_Admin, async (request, response) => {

  const data = await client.db("ecommerce").collection("user").find({role:"vendor"}).toArray()

  response.send(data);

});

//! My Products for Seller (GET)
//? Seller can view his own product

app.get('/seller/myProducts',auth_vendor,async(request,response)=>{
  
  const headerToken = request.header("x-auth-token")

  const responseData = jsonwebtocken.verify(headerToken,process.env.privateKey1);

  const getReferance = responseData._id;

  const findProducts = await client.db("ecommerce").collection("products").find({userId:getReferance}).toArray()

  console.log(findProducts);

  response.send(findProducts)

})

//! Request for admitting product.
//? Seller Only.

app.post("/request/products",auth_vendor,(request,response)=>{

  const headerToken = request.header("x-auth-token")

  const responseData = jsonwebtocken.verify(headerToken,process.env.privateKey1);

  const referanceObject = responseData._id;

  const {name,productType,poster,summary,price,Approvel} = request.body;

  const pushData = {
    name:name,
    userId:referanceObject,
    productType:productType,
    poster:poster,
    summary:summary,
    price:price,
    Approvel:Approvel
  }

  const addProduct = client
  .db("ecommerce")
  .collection("products")
  .insertOne(pushData);

  if(!addProduct){
 response.status(401).send("Bad request")
  }else{
    response.send("Request sent sucessfully")
  }
})


//! Admin update his own info.
//?  seller Only.

app.put("/edit/user", auth_vendor, async (request, response) => {

  const hearderToken = request.header("x-auth-token");

  const { _id, name, email, contact, password, userDp,district } = request.body;

  const hashedPassword = await createPassword(password);

  const updateData = {
    name: name,
    email: email,
    contact: contact,
    password: hashedPassword,
    userDp: userDp,
    district:district
  };

  const responseData = jsonwebtocken.verify(
    hearderToken,
    process.env.privateKey1
  );

  const updateReferance = responseData._id;

  const changeUserData = client
    .db("ecommerce")
    .collection("user")
    .updateOne({ _id: ObjectId(`${updateReferance}`) }, { $set: updateData });

  response.send("User Updated Successfully");

});

app.listen(PORT, () => console.log(`Server connected on port ${PORT} 😊😊`));

//! DataBase Connection

async function createConnection() {
  const client = new MongoClient(MONGO_URL);

  await client.connect();

  console.log("MongoDb is connected to server 👍🏽");

  return client;
}

// ?  Hashing and salting process before storing a password in DB

async function createPassword(password) {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  return hash;
}

//? TOKEN GENERATOR

const tokenGenerator = async (email) => {
  const token = jsonwebtocken.sign({ email }, process.env.privateKey3, {
    expiresIn: "3hours",
  });
  return token;
};
