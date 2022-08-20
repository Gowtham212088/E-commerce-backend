import express, { response } from "express";
import { MongoClient, ObjectId } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import jsonwebtocken from "jsonwebtoken";
import { request } from "http";
import { v4 as uuidv4 } from "uuid";
import Stripe from "stripe";

//! Configuring Enviroinment variables
dotenv.config();
const KEY = process.env.stripe_key;
const stripe = new Stripe(KEY, {
  apiVersion: "2020-08-27",
});

const app = express();

//! Express MiddleWare (Body Parser)
app.use(express.json({ limit: "50mb" }));

const auth_Admin = (request, response, next) => {
  const token = request.header("x-auth-token");

  const verifyToken = jsonwebtocken.verify(token, process.env.privateKey1);
  if (verifyToken.role === "Admin") {
    next();
  } else {
    response.status(401).send({ error: err.message });
  }
};

//! Custom Middleware for Admin session

const auth_vendor = (request, response, next) => {
  const token = request.header("x-auth-token");

  const verifyToken = jsonwebtocken.verify(token, process.env.privateKey1);
  if (verifyToken.role === "vendor") {
    next();
  } else {
    response.status(401).send({ error: err.message });
  }
};

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

app.post("/create/users", async (request, response) => {
  const { name, email, password, image, role, district } = request.body;

  // !  PASSWORD HASHING PROCESS
  //? ADMIN ONLY

  const hashPassword = await createPassword(password);

  const newUser = {
    name: name,
    email: email,
    password: hashPassword,
    role: role,
    district: district,
    userDp: image,
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
app.get("/products/customers/:id", async (request, response) => {
  const { id } = request.params;

  const getAllData = await client
    .db("ecommerce")
    .collection("products")
    .find()
    .toArray();

  const filterApproved = getAllData.filter((element) => {
    return element.Approvel === true;
  });

  response.send(filterApproved[id]);
});

//! Get all approved products.
app.get("/products/customers", async (request, response) => {
  const getAllData = await client
    .db("ecommerce")
    .collection("products")
    .find()
    .toArray();

  const filterApproved = getAllData.filter((element) => {
    return element.Approvel === true;
  });

  response.send(filterApproved);
});

//! Get all approved products.
app.get("/products/admin", auth_Admin, async (request, response) => {
  const getAllData = await client
    .db("ecommerce")
    .collection("products")
    .find()
    .toArray();

  const filterApproved = getAllData.filter((element) => {
    return element.Approvel === false;
  });

  response.send(filterApproved);
});

//! Product approval from Admin (PUT)

app.put("/delete/product/:id", auth_Admin, async (request, response) => {
  const { id } = request.params;

  const hearderToken = request.header("x-auth-token");

  const findProducts = await client
    .db("ecommerce")
    .collection("products")
    .find()
    .toArray();

  //? Here we filtering non-approved products.
  const filterApproval = findProducts.filter((element) => {
    return element.Approvel === false;
  });

  const refProducts = filterApproval[id]._id;

  const changeApprovalStatus = await client
    .db("ecommerce")
    .collection("products")
    .updateOne(
      { _id: ObjectId(`${refProducts}`) },
      { $set: { Approvel: true } }
    );

  response.send(changeApprovalStatus);
});

//!  LOGIN VERIFICATION
//?  BOTH A SELLER AND ADMIN
app.post("/user/signIn", async (request, response) => {
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
          name: signIn.name,
          email: signIn.email,
          role: signIn.role,
          district: signIn.district,
          picture: signIn.userDp,
          product: signIn.product,
        },
        process.env.privateKey1
      );
      response.send({
        message: `Welcome ${signIn.name}`,
        token: token,
        status: "Successful",
      });
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
    .db("ecommerce")
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

    sender
      .sendMail(composemail)
      .then((response, request) => {
        response.send({
          to: email,
          subject: subject,
          message:
            "Please Click the link below to reset the passsword for security reasons the link will be expired in the next 10 minute",
        });
      })
      .catch((error) => {
        response.send(error);
      });
  }
});

//?  BOTH A SELLER & ADMIN

app.post("/new-password/:_id/:token", async (request, response) => {
  const { _id } = request.params;

  const { token } = request.params;

  const { password, newPassword } = request.body;

  const conformId = await client
    .db("ecommerce")
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
          .db("ecommerce")
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

  const data = await client
    .db("ecommerce")
    .collection("user")
    .findOne({ _id: ObjectId(`${getId}`) });

  response.send(data);
});

//// TESTED OK (WITH ADMIN LOGIN)
//! Admin's information only.
//? Admin Only.

app.get("/get/adminData", auth_Admin, async (request, response) => {
  const getDatas = request.header("x-auth-token");

  const crackData = jsonwebtocken.verify(getDatas, process.env.privateKey1);

  const getId = crackData._id;

  const data = await client
    .db("ecommerce")
    .collection("user")
    .findOne({ _id: ObjectId(`${getId}`) });

  response.send(data);
});

//! Get all products for approval purposes.
// ? Admin only

app.get("/get/allProducts", auth_Admin, async (request, response) => {
  const getDatas = request.header("x-auth-token");

  const crackData = jsonwebtocken.verify(getDatas, process.env.privateKey1);

  if (crackData.role === "Admin") {
    const data = await client
      .db("ecommerce")
      .collection("products")
      .find()
      .toArray();
  }
  response.send(crackData);
});

//// TESTED OK WITH (ADMIN LOGIN)
//! Users informations for Admin.
//? Admin Only.

app.get("/get/allUsersData", auth_Admin, async (request, response) => {
  const data = await client
    .db("ecommerce")
    .collection("user")
    .find({ role: "Vendor" })
    .toArray();

  response.send(data);
});

//! My Products for Seller (GET)
//? Seller can view his own product

app.get("/seller/myProducts/userId/:userId", async (request, response) => {
  const findProducts = await client
    .db("ecommerce")
    .collection("products")
    .find({ userId: request.params.userId })
    .toArray();

  response.send(findProducts);
});

//! Request for admitting product.
//? Seller Only.

app.post("/request/products", (request, response) => {
  const { name, userId, productType, poster, summary, price, Approvel } =
    request.body;

  const pushData = {
    name: name,
    userId: userId,
    productType: productType,
    poster: poster,
    summary: summary,
    price: price,
    Approvel: Approvel,
  };

  const addProduct = client
    .db("ecommerce")
    .collection("products")
    .insertOne(pushData);

  if (!addProduct) {
    response.status(401).send("Bad request");
  } else {
    response.send("Request sent sucessfully");
  }
});

//! Admin update his own info.
//?  seller Only.

app.put("/edit/user", auth_vendor, async (request, response) => {
  const hearderToken = request.header("x-auth-token");

  const { _id, name, email, contact, password, userDp, district } =
    request.body;

  const hashedPassword = await createPassword(password);

  const updateData = {
    name: name,
    email: email,
    contact: contact,
    password: hashedPassword,
    userDp: userDp,
    district: district,
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

//! Get seller by ID
app.get("/edit/users/:id", auth_Admin, async (request, response) => {
  const { id } = request.params;

  const hearderToken = request.header("x-auth-token");

  const findProducts = await client
    .db("ecommerce")
    .collection("user")
    .find()
    .toArray();

  const filterProducts = findProducts.filter(
    (element) => element.role === "Vendor"
  );

  response.send(filterProducts[id]);
});

//! User Information to Admin

app.get("/user/getInfo", auth_Admin, async (request, response) => {
  const getData = await client
    .db("ecommerce")
    .collection("orders")
    .find()
    .toArray();

  const mapData = getData.map((elem) => {
    return {
      name: elem.token.card.name,
      email: elem.token.email,
      Address: elem.token.card.address_line1,
      country: elem.token.card.address_country,
      city: elem.token.card.address_city,
      pincode: elem.token.card.address_zip,
      money_spent: elem.total,
    };
  });

  response.send(mapData);
});

//! GET purchase INFO for ADMIN.

app.get("/user/purchaseInfo", auth_Admin, async (request, response) => {
  const getData = await client
    .db("ecommerce")
    .collection("orders")
    .find()
    .toArray();

  const mapData = getData
    .map((elem) => {
      return elem.product;
    })
    .flat();

  response.send(mapData);
});

//? DELETE users by ID
app.delete("/delete/users/:id", auth_Admin, async (request, response) => {
  const { id } = request.params;

  const hearderToken = request.header("x-auth-token");

  const findProducts = await client
    .db("ecommerce")
    .collection("user")
    .find()
    .toArray();

  const filterProducts = findProducts.filter(
    (element) => element.role === "Vendor"
  );

  const referanceData = filterProducts[id]._id;

  const deleteData = await client
    .db("ecommerce")
    .collection("user")
    .deleteOne({ _id: referanceData });

  response.send(deleteData);
});

//!  Stripe Payment

app.post("/checkout", async (req, res) => {
  console.log(req.body);
  let error;
  let status;
  try {
    const { product, token } = req.body;
    const customer = await stripe.customers.create({
      name: token.name,
      email: token.email,
      source: token.id,
    });
    const idempontencyKey = uuidv4();
    const charge = await stripe.charges.create(
      {
        amount: product.price,
        currency: "INR",
        customer: customer.id,
        receipt_email: token.email,
        description: `Purchased the ${product.name}`,
        shipping: {
          name: token.card.name,
          address: {
            line1: token.card.address_line1,
            line2: token.card.address_line2,
            city: token.card.address_city,
            country: token.card.address_country,
            postal_code: token.card.address_zip,
          },
        },
      },
      {
        idempontencyKey,
      }
    );
    console.log("Charge:", { charge });
    status = "success";
  } catch (error) {
    console.log("Error:", error);
    status = "failure";
  }
  res.json({ error, status });
});

app.post("/create/orderInfo", async (request, response) => {
  const { token, product, total } = request.body;

  const user = {
    token: token,
    product: product,
    total: total,
  };

  const findProducts = await client
    .db("ecommerce")
    .collection("orders")
    .insertOne(user);

  response.send(findProducts);
});

app.get("/get/orderInfo", auth_Admin, async (request, response) => {
  // const {id}= request.body;

  const findProducts = await client
    .db("ecommerce")
    .collection("orders")
    .find()
    .toArray();

  response.send(findProducts);
});

app.delete("/delete/orderInfo", async (request, response) => {
  const userId = request.body;

  const findProducts = await client
    .db("ecommerce")
    .collection("orders")
    .findOneAndDelete(userId);

  response.send(findProducts);
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
