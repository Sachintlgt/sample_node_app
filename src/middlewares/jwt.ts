import { Request, Response, NextFunction } from 'express';
import * as jwt from "jsonwebtoken";
import apiResponse from "../helpers/apiResponse";
import responseCode from '../helpers/response';


const getToken = (request: Request, response: Response, next: NextFunction) => {

}

const authenticateJWT = (request: Request, response: Response, next: NextFunction) => {
    let authHeader: string | any = request.cookies.token || request.headers.token || null;
    //console.log("Get cookie on server ==>>>",request.cookies.token); // remove this line after resolving cookie issue

    if (authHeader) {

        jwt.verify(authHeader, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return apiResponse.unauthorizedResponse(response, "GEN0005");
            }
            request.headers.userId = user.id;
            request.headers.userRole = user.roleIds;
            
            
            next();
        });
    } else {
        return apiResponse.unauthorizedResponse(response, "GEN0005");
    }
}


const authenticateJWTSocket = (socket) => {
    let authHeader: string | any = socket.handshake.query ? socket.handshake.query.token : null;
  //  console.log("Get cookie on server ==>>>",request.cookies.token); // remove this line after resolving cookie issue
    
  if (authHeader) {

        jwt.verify(authHeader, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                socket.emit('errorHandler', { error: true, data: null, msg: responseCode['GEN0005'].msg, code: responseCode['GEN0005'].code })
            }

            socket.handshake.query.userId = user.id;

            return false;
        });

    } else {
        socket.emit('errorHandler', {error: true, data: null, msg: responseCode['GEN0005'].msg, code: responseCode['GEN0005'].code} )
    }
}



export {authenticateJWT, authenticateJWTSocket};
