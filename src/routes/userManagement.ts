
import * as express from 'express';
import userManagementController from  "../controllers/userManagementController";
import * as multer from'multer';
const upload = multer();

/* GET home page. */

class userManagement {
    private userManagementController: userManagementController;
    private router: express.Router;


    constructor(){
        this.userManagementController = new userManagementController();
        this.router = express.Router();
    }
    public route(): any {

        this.router.get("/get-roles-count",this.userManagementController.getUserRoleCount());
        this.router.get("/filters-list",this.userManagementController.getUserFilterList());
        this.router.get("/get-roles-list",this.userManagementController.getUserRolesList());
        this.router.get("/user-details/:userId",this.userManagementController.getUserDetail());
        this.router.post("/create-user",this.userManagementController.createUser());
        this.router.put("/edit-profile/:userId",this.userManagementController.editProfile());
        this.router.post("/get-users-list",this.userManagementController.getUsersList());
        this.router.put("/update-status",this.userManagementController.updateUsersStatus());
        this.router.post("/is-user-exist",this.userManagementController.isUserExist());

        return this.router;
    }
}

export default userManagement;
