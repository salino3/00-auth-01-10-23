import {RequestHandler} from 'express';
import jwt from 'jsonwebtoken';
import {envConstants} from '#core/constants/index.js';
import { UserSession } from '#common-app/models/users-session.js';
import { Role } from '#common-app/models/role.js';

 const verify = (token: string, secret: string): Promise<UserSession>  => new Promise((resolve, reject) => {
    jwt.verify(token, secret, (error, userSession: UserSession) => {
      if(error){
        reject(error);
      }
      if(userSession){
        resolve(userSession)
      }else{
        reject();
      }
    })
 })

export const autenticationMiddleware: RequestHandler = async (req, res, next) => {

    try {
  const [, token] = req.headers.authorization?.split(' ') || [];
  const userSession = await verify(token , envConstants.SECRET_WORD);
  req.userSession = userSession;
  next();
    } catch (error) {
   res.sendStatus(401);
    }
};

const isAuthorezed = (currentRole: Role, allowedRoles?: Role[]) =>
!Boolean(allowedRoles) || (Boolean(currentRole) && allowedRoles.some((role) => currentRole === role));





export const authorizationMiddleware = (allowedRoles?: Role[]): RequestHandler => async (req, res, next) => {

 if(isAuthorezed(req.userSession?.role, allowedRoles)) {
  next()
 }else{
  res.sendStatus(403);
 }
}




