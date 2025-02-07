const localStrategy= require('passport-local').Strategy;
const mongoose = require ('mongoose');
const bcrypt = require('bcryptjs');

//Load User Model

const User = require('../models/User');

module.exports = function(passport){

    passport.use(
        new localStrategy({usernameField:'email'},(email,password,done)=>{

            //Match User
            User.findOne({email:email})
            .then(user=>{
                if(!user){
                    return done(null,false,{message:'That email is not registered'})
                }

                //Match password
                bcrypt.compare(password,user.password, (err,isMatch)=>{

                    if(err) throw err;
                    if(isMatch){
                        return done(null,user)
                    }else{
                        return done(null,false,{message:'Password incorrect'})
                    }

                })
            })
            .catch(err=> console.log(err));

        })
    );

    passport.serializeUser((user, done)=> {
        done(null, user.id);
      });
      
      passport.deserializeUser(async (id, done) => {
        try {
            // Use async/await to find the user by ID
            const user = await User.findById(id);
            done(null, user);  // Pass the user to the session
        } catch (err) {
            console.error(err);  // Log error for debugging
            done(err, null);  // Pass the error to done callback
        }
    });



};