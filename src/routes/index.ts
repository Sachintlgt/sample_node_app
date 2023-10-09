import * as express from 'express';
/* GET home page. */

class Index{

	private router;

	constructor(){
		this.router = express.Router();
	}

	public route(): any{

		this.router.get("/",function(req: express.Request, res: express.Response) {
			res.status(200).json({status:false,message:`Welcome to ${process.env.APP_NAME} api.`});
		});

		return this.router;
	}
}

export default Index;
