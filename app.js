const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const jwtGenerator = require("./jwtgenerator")
const saltRounds = 10;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect('mongodb://localhost:27017/firstTask',{useNewUrlParser: true});

const userSchema = {
  name:String,
  mobileNumber:Number,
  email:String,
  password:String
}

const User = new mongoose.model("User",userSchema)

app.get("/",(req, res)=>{
    res.render("signup");
})

app.get("/login",(req, res)=>{
    res.render("login");
  });

app.post("/",async(req, res)=>{

  const { name, mobileNumber, email, password } = req.body;

  const foundMobileNumber = await User.findOne({ mobileNumber: mobileNumber }).exec();
  if (foundMobileNumber) return res.status(409).json({status:409,message:"Number Already exist!"});
  const foundUser = await User.findOne({ email: email }).exec();
  if (foundUser) return res.status(409).json({status:409,message:"User Already exist!"});

  bcrypt.hash(password, saltRounds, function(err, hash) {
    const access_token = jwtGenerator(email);
    const newUser = new User({
      name:name,
      mobileNumber:mobileNumber,
      email:email,
      password:hash
    });

    newUser.save(function(err){
      if(err){
        console.log(err);
      }else{
        res.render("success");
      }
    });
    res.json({token:access_token});
  });
});

app.post("/login",(req,res)=>{
  const { email, password } = req.body;
    if (!password || !email)
      return res.status(400).json({ message: 'Email and Password is required' });

  User.findOne({email:email}, (err, foundUser)=>{
    if(err){
       res.json({message:err})
    } else {
      if(foundUser){
        const access_token = jwtGenerator(email);
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result){
            res.render('success');
            res.json({token:access_token});
          }else{
            res.json({message:"invalid password!"})
          }

        });
      } else {
        return res.status(401).json({status:401,message:"User does not exisit!"});
        console.log(err);
      }
    }
  })
})

app.listen(3000,()=>{
    console.log("server started on port 3000!");
});
