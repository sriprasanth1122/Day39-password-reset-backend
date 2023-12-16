const express = require("express");
const app = express();
var bodyParser = require('body-parser')
const mongodb = require("mongodb")
const dotenv = require("dotenv").config()
const bcrypt = require("bcryptjs")
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer')
const cors = require("cors")
const mongoClient = mongodb.MongoClient

const URL = process.env.DB;
const DB = "loginLogout";


//middleware
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())


app.use(cors({
    origin:process.env.BASE_URL
  }))


// user register
app.post("/register", async (req, res) => {

    try {
      // Step 1 : Create a Connection between Nodejs and MongoDB
      const connection = await mongoClient.connect(URL);
  
      // Step 2 : Select the DB
      const db = connection.db(DB);
  

          // first to check the email in database
          let user = await db.collection("users").findOne({ email: req.body.email })
  
          if (!user) {
     // salt generation

     let salt = await bcrypt.genSalt(10);
     let hash = await bcrypt.hash(req.body.password, salt);
 
     req.body.password = hash

     // Step 3 : Select the Collection
     // Step 4 : Do the operation (Create,Update,Read,Delete)
     await db.collection("users").insertOne(req.body);

     res.json({
      statusCode: 201,
      message: " user Register Successfully"
    })
          } else {
            res.json({
              statusCode: 401,
              message: "Email address is already exists"
            })
          }

 
  
      // Step 5 : Close the connection
      await connection.close();
  
      
    } catch (error) {
      console.log(error);
      // If any error throw error
      res.json({
        statusCode: 500,
        message: "Internal Server Error",
        error
      })
    }
  });
  
  
  // user login 
  app.post("/login", async (req, res) => {
  
    try {
      // Step 1 : Create a Connection between Nodejs and MongoDB
      const connection = await mongoClient.connect(URL);
  
      // Step 2 : Select the DB
      const db = connection.db(DB);
  
      // first to check the email in database
      let user = await db.collection("users").findOne({ email: req.body.email })
  
      if (user) {
        // compare the two password
        let compare = await bcrypt.compare(req.body.password, user.password)
        if (compare) {
          let token = jwt.sign({ id: user._id },process.env.SECRETKEY, { expiresIn: "1m" });
          res.json({
            statusCode:201,
            message: "login successfully",
            token,
            user,
          })
        } else {
          res.json({
            statusCode: 401,
            message: "Invaild Email / Password"
          })
        }
      } else {
        res.json({
          statusCode: 401,
          message: "Invaild Email / Password"
        })
      }
      // Step 5 : Close the connection
      await connection.close();
    } catch (error) {
      console.log(error);
      // If any error throw error
      res.json({
        statusCode: 500,
        message: "Internal Server Error",
        error
      })
    }
  });

  // Forget password send in mail

  app.post("/reset-sendmail", async (req, res) => {
  try {
    // Step 1 : Create a Connection between Nodejs and MongoDB
    const connection = await mongoClient.connect(URL);

    // Step 2 : Select the DB
    const db = connection.db(DB);

    // first to check the email in database
    let user = await db.collection("users").findOne({ email: req.body.email });

    if (user) {
      let token = jwt.sign({ id: user._id }, process.env.SECRETKEY, {
        expiresIn: "10m",
      });
      let url = `${process.env.BASE_URL}/password/${user._id}/${token}`;

      let transporter = nodemailer.createTransport({
        service: "gmail",
        host: "smtp.gmail.com",
        port: 993,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.EMAILUSE, // generated ethereal user
          pass: process.env.EMAILPASS, // generated ethereal password
        },
      });
      let details = {
        from: "sivanathanv36@gmail.com", // sender address
        to: user.email, // list of receivers
        subject: "Hello ✔", // Subject line
        text: `Reset link`, // plain text body
        // html: "<b>Hello world?</b>", // html body
        html: `<div style=" border:3px solid blue; padding : 20px;"><span>Password Reset Link : - </span> <a href=${url}> Click
        here !!!</a>

    <div>
        <h4>
            Note :-
            <ul>
                <li>This link only valid in 10 minitues</li>
            </ul>
        </h4>
    </div>
</div>`,
      };

      await transporter.sendMail(details, (err) => {
        if (err) {
          res.json({
            statusCode: 200,
            message: "it has some error for send a mail",
          });
        } else {
          res.json({
            statusCode: 200,
            message: "Password Reset link send in your mail",
          });
        }
      });
    } else {
      res.json({
        statusCode: 401,
        message: " Please enter vaild email address",
      });
    }

    // Step 5 : Close the connection
    await connection.close();
  } catch (error) {
    res.json({
      statusCode: 500,
      message: "Internal Server Error",
      error,
    });
  }
});




// authenticate for for got password 
  const authenticate = (req, res, next) => {
    // check the token in body
    if (req.body.token) {
      try {
        // check the token is valid or not
        let decode = jwt.verify(req.body.token, process.env.SECRETKEY)
        if (decode) {
          next();
        }
  
      } catch (error) {
        res.json({
          statusCode: 401,
          message: "Your token is expiry",
          error,
        })
      }
  
    } else {
      res.json({
        message: 401,
        statusbar: "unauthorized"
      })
    }
  
  }
  


  // Password Reset Form

  app.post("/password-reset",authenticate, async(req,res)=>{
try {


   const connection = await mongoClient.connect(URL);
  

   const db = connection.db(DB);
// hash the password
   let salt = await bcrypt.genSalt(10);
   let hash = await bcrypt.hash(req.body.password, salt);

   req.body.password = hash

   // update the password in database
   await db.collection("users").updateOne({ _id: mongodb.ObjectId(req.body.id)},{$set:{ password: req.body.password }})
res.json({
    statusCode: 201,
    message:"Password Reset successfully",
  })
    
} catch (error) {
    
}

  })
  
  
  app.listen(process.env.PORT || 4000);





