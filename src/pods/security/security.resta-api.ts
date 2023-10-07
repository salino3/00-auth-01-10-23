import {Router} from 'express';
import { userRepository } from '#dals/index.js';
import jwt from 'jsonwebtoken';
import { UserSession } from '#common-app/models/index.js';
import { envConstants } from '#core/constants/index.js';


export const securityApi = Router();

// login



// logout



securityApi.post('/login', async (req, res, next) => {

  try {
    const {email, password} = req.body;

  // Check is valid user
  const user = await userRepository.getUserByEmailAndPassword(email, password);

    if(user){

      const userSession: UserSession = {
        id: user._id.toHexString()
      };

      const secret = process.env.SECRET_WORD;
      const token = jwt.sign(userSession, secret, {
        expiresIn: '1d',
        algorithm: 'HS256'
      });

      res.send(`Bearer ${token}`);

    }else{
      res.sendStatus(401);
    };

  } catch (error) {
    next(error);
  };
})








