const jwt = require('jsonwebtoken');
const config = require('config');


//middleware so req res and next
module.exports = function(req,res,next) {

    //Get token from header
    const token = req.header('x-auth-token');

    if(!token){
        return res.status(401).json({msg:'No token , authorisation denied'});
    }

    //Verify Token
    try {
        const decoded = jwt.verify(token , config.get('jwtSecret'));
        req.user = decoded.user;
        next(); 
    }catch(err) {
        res.status(401).json({msg: 'Token is not valid !!'});   
    }
}