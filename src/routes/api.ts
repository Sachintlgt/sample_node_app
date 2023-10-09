import * as express from 'express';
import AuthRouter from './auth';
import UsersRouter from './userManagement';
import PlantsRouter from './plants';
import AdditivesRouter from './additives';
import ProductsRouter from './products';
import SuppliersRouter from './suppliers'
import SupportRouter from './support';
import ProjectSettingRouter from './projectSettings';
import AdditiveReplacement from './additiveReplacement';

/* GET home page. */

class Api{
	private authRouter : AuthRouter;
	private usersRouter : UsersRouter;
	private plantsRouter: PlantsRouter;
	private additivesRouter: AdditivesRouter;
	private productsRouter: ProductsRouter;
	private suppliersRouter: SuppliersRouter;
	private supportRouter: SupportRouter;
	private projectSettingRouter: ProjectSettingRouter;
	private additiveReplacementRouter : AdditiveReplacement;
	private app: express.Application
	constructor(){
	 	this.authRouter = new AuthRouter();
	 	this.usersRouter = new UsersRouter();
	 	this.plantsRouter = new PlantsRouter();
	 	this.additivesRouter = new AdditivesRouter();
		this.productsRouter = new ProductsRouter();
		this.suppliersRouter = new SuppliersRouter();
		this.supportRouter = new SupportRouter();
		this.projectSettingRouter = new ProjectSettingRouter();
		this.additiveReplacementRouter = new AdditiveReplacement();
		this.app = express();
	}
	public route(): express.Application{
        
		this.app.use("/auth/", this.authRouter.route());
		this.app.use("/users/", this.usersRouter.route());
		this.app.use("/plants/", this.plantsRouter.route());
		this.app.use("/additives/", this.additivesRouter.route());
		this.app.use("/products/", this.productsRouter.route());
		this.app.use("/suppliers/", this.suppliersRouter.route());
		this.app.use("/support/", this.supportRouter.route());
		this.app.use("/project/", this.projectSettingRouter.route());
		this.app.use("/additiveReplacements/", this.additiveReplacementRouter.route());

		return this.app;
	}
}

export default Api;
