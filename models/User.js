    const mongoose = require('mongoose')
    const bcrypt = require('bcrypt')
    const userSchema = new mongoose.Schema({
        username : {
            type : String,
            required : true
        },
        email : {
            type : String,
            required : true,
            unique : true
        },
        password : {
            type : String
        },
        role : {
            type : String,
            required : true,
        },
        image : {
            type : String
        },
        authProvider : {
            type : String
        },
        authProviderId : {
            type : String
        }
    })
    userSchema.pre('save',async function(next){
        if (this.isModified('password') && this.password) { 
            const salt =await bcrypt.genSalt();
            this.password = await bcrypt.hash(this.password,salt);
            next();
        }
    })
    userSchema.statics.login=async function(email, password){
        const user = await this.findOne({email});
        if(user && !user.password)
            {
                throw Error('auth using google');
            }
        if(user)
        {
            const auth = await bcrypt.compare(password, user.password);
            if(auth)
                {
                    return user;
                }
            throw Error("incorrect password")

        }
        throw Error("incorrect email");
    }
    const User = mongoose.model('user', userSchema);
    module.exports = User;