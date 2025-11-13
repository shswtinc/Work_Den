//we make the healthcheck system with goal of telling the world that our server is up and running and prove its worth to contact and exchange data with outside world services like cloud providers and DevOps tools
//now we are working in controllers coz controllers contains the business logic , so as of now we defining the logic of healthcheck system ,i.e. just ro send a success code , 200 Success 
import { APIResponse } from '../utils/api-response.js';
import { asyncHandler } from '../utils/asyncHandlers.js';
const healthCheck = asyncHandler(async (req, res) => {
    res
        .status(200)
        .json(new APIResponse(200, { message: "Server running...AH" }));
})
export default healthCheck;
