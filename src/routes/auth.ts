
import * as express from 'express';
import AuthController from  "../controllers/authController";
import * as multer from'multer';
const upload = multer();

/* GET home page. */

class Auth {
    private authController: AuthController;
    private router: express.Router;


    constructor(){
        this.authController = new AuthController();
        this.router = express.Router();
    }
    public route(): any {

        this.router.post("/forgot-password", this.authController.forgotPassword());
        this.router.post("/verify-otp", this.authController.otpVerification());
        this.router.post("/reset-password", this.authController.passwordResetting());
        this.router.post("/register",this.authController.register());
        this.router.post("/login",this.authController.login());
        this.router.get("/user-details/:userId",this.authController.userDetail());
        this.router.get("/user-list",this.authController.userList());
        this.router.put("/change-password",this.authController.changePassword());
        this.router.put("/edit-profile",this.authController.editProfile());
        this.router.put("/update-user-status",this.authController.updateUserStatus());
        this.router.delete("/delete-user/:userId",this.authController.deleteUser());
        this.router.put("/update-profile", upload.any(), this.authController.updateProfile());

        return this.router;
    }
}

export default Auth;
