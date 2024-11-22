const express = require('express');
const app = express();
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, UpdateCommand, ScanCommand, PutCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const port = 3000;
require('dotenv').config();

// getting the file that stores all the messages strings for the responses
const messages = require('./utils/messages');

app.use(bodyParser.json());

// getting the validation functions from the utils/validators.js file
const { validateRegistration,validateLogin,validateAdviceInputs,validateUpdateRequestCount, } = require('./utils/validators');

// swagger documentation
const swaggerUi = require('swagger-ui-express');
const yaml = require('yamljs');
const swaggerDocument = yaml.load('./swagger.yaml');
app.use('/doc', swaggerUi.serve, swaggerUi.setup(swaggerDocument));



// Enable CORS for any origin (or specify allowed origins)
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Specify your frontend URL
    methods: 'GET,POST,PUT,DELETE',
    allowedHeaders: 'Content-Type,Authorization',
}));

// Create a DynamoDB client
const client = new DynamoDBClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

const dynamoDB = DynamoDBDocumentClient.from(client);


// Create a function to log user requests
const logUserRequest = async (email, name) => {
    const params = {
        TableName: 'UserRequests',
        Key: { email },
        UpdateExpression: 'SET requestCount = if_not_exists(requestCount, :start) + :inc, lastRequestTimestamp = :timestamp, #userName = :name',
        ExpressionAttributeValues: {
            ':inc': 1,
            ':start': 0,
            ':timestamp': new Date().toISOString(),
            ':name': name, // Store the user's name
        },
        ExpressionAttributeNames: {
            '#userName': 'name', // Use a placeholder for the reserved word 'name'
        },
    };

    await dynamoDB.send(new UpdateCommand(params));
};

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from the Authorization header
    if (!token) return res.status(403).send({ error: messages.errors.noToken });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ error: messages.errors.unauthorized });
        req.userEmail = decoded.email;
        req.userName = decoded.name; // Store the user's email in the request object for later use
        next();
    });
};

// Middleware to log endpoint stats
const logEndpointRequest = async (req, res, next) => {
    const { method, originalUrl } = req; // Get the HTTP method and endpoint
    const params = {
        TableName: 'EndpointStats',
        Key: {
            endpoint: originalUrl,
            method: method,
        },
        UpdateExpression: 'SET requestCount = if_not_exists(requestCount, :start) + :inc',
        ExpressionAttributeValues: {
            ':start': 0,
            ':inc': 1,
        },
    };

    try {
        // Update the stats in the database
        await dynamoDB.send(new UpdateCommand(params));
    } catch (error) {
        console.error('Error logging endpoint request:', error);
    }
    next(); // Continue to the next middleware/handler
};

app.use(logEndpointRequest); // Use this middleware for all routes



// New endpoint to get the request count
app.get('/requestCount', verifyToken, async (req, res) => {
    const email = req.userEmail; // Get the user's email from the request object

    const requestCountParams = {
        TableName: 'UserRequests',
        Key: { email },
    };

    try {
        // Use GetCommand to retrieve the item
        const requestCountData = await dynamoDB.send(new GetCommand(requestCountParams));
        const requestCount = requestCountData.Item ? requestCountData.Item.requestCount || 0 : 0;
         // Check if request count has exceeded 20
         const response = { requestCount };
         if (requestCount >= 20) {
             response.warning = messages.warnings.freeLimitExceeded;
         }
 
         res.json(response); // Return the request count and the warning if applicable // Return the request count
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: messages.errors.requestCountError });
    }
});


app.post('/register',validateRegistration, async (req, res) => {
    const { name, email, password } = req.body;

    // Check if the user with the given email already exists
    const checkParams = {
        TableName: 'authentication',
        Key: {
            email: email,
        },
    };

    try {
        const existingUser = await dynamoDB.send(new GetCommand(checkParams));

        if (existingUser.Item) {
            return res.status(400).json({ error: messages.errors.emailExists });
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 10);

        const params = {
            TableName: 'authentication',
            Item: {
                email,
                isAdmin: false,
                name,
                password: hashedPassword,
            },
        };

        await dynamoDB.send(new PutCommand(params));

        res.status(201).json({ message: messages.success.userRegistered });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});

app.post('/login', validateLogin, async (req, res) => {
    const { email, password } = req.body;

    const params = {
        TableName: 'authentication',
        Key: { email },
    };

    try {
        const data = await dynamoDB.send(new GetCommand(params));
        const user = data.Item;

        if (!user) {
            return res.status(401).json({ error: messages.errors.invalidCredentials });
        }

        // Compare the provided password with the hashed password in the database
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).json({ error: messages.errors.invalidCredentials });
        }

        // Generate a JWT
        const token = jwt.sign({ email: user.email, name: user.name, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Log the user request with user's name
        await logUserRequest(email, user.name); // Pass the user's name here

        res.json({ token ,isAdmin:user.isAdmin}); // Return the JWT to the client
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error logging in' });
    }
});

// New endpoint to get user request data
app.get('/userRequests', verifyToken, async (req, res) => {
    const email = req.userEmail; // Get the user's email from the request object

    // Check if the user is an admin
    const adminCheckParams = {
        TableName: 'authentication',
        Key: { email },
    };

    try {
        const adminCheckData = await dynamoDB.send(new GetCommand(adminCheckParams));
        const user = adminCheckData.Item;

        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const requestsParams = {
            TableName: 'UserRequests',
        };

        const requestsData = await dynamoDB.send(new ScanCommand(requestsParams));
        res.json(requestsData.Items); // Return the list of user requests
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: messages.errors.userRequestError });
    }
});

// New endpoint to get health advice
app.post('/getAdvice', verifyToken, validateAdviceInputs, async (req, res) => {
    const { age, name, behavior } = req.body;
    const email = req.userEmail;
     // Get the user's email from the request object

    try {
        // Log the getAdvice request
        await logUserRequest(email, name);
        // Send request to the Flask server
        const flaskResponse = await axios.post('https://isa-project-flask.onrender.com/getAdvice', {
            age,
            name,
            behavior
        });

        
        // Return the response from the Flask server back to the client
        res.json(flaskResponse.data); // Send back the advice received from Flask server
    } catch (error) {
        console.error(messages.errors.adviceError, error);
        res.status(500).json({ error: messages.errors.adviceError }); // Handle error
    }
});

app.post('/translate', verifyToken, async (req, res) => {
    const { text, language } = req.body;
    const email = req.userEmail; // Get the user's email from the request object
    const name = req.userName; // Get the user's name from the request object
    console.log("email",email);
    

    // Validate input
    if (!text || !language) {
        return res.status(400).json({ error: "Text and target language are required." });
    }

    try {

        // // Log the getAdvice request
        await logUserRequest(email, name);
        // Send the request to the Flask translation service
        const flaskResponse = await axios.post('https://testing-model-kn0h.onrender.com/translate', {
            text,
            language,
        });

        // Forward the Flask service response back to the client
        res.json(flaskResponse.data);
    } catch (error) {
        console.error('Error calling translation service:', error.message);
        res.status(500).json({ error: 'An error occurred while processing the translation.' });
    }
});


// endpoint to edit the api usage of the user
app.put('/updateRequestCount', verifyToken, validateUpdateRequestCount, async (req, res) => {
    const email = req.body.email; // Email of the user to update
    const newRequestCount = req.body.requestCount; // New request count value

    try {
        // Update the request count in the UserRequests table
        const params = {
            TableName: 'UserRequests',
            Key: { email },
            UpdateExpression: 'SET requestCount = :requestCount',
            ExpressionAttributeValues: {
                ':requestCount': newRequestCount,
            },
        };

        await dynamoDB.send(new UpdateCommand(params));
        res.json({ message: messages.success.requestCountUpdated });
    } catch (error) {
        console.error('Error updating request count:', error);
        res.status(500).json({ error: messages.errors.updateRequestError });
    }
});

// Endpoint to fetch stats for all endpoints
app.get('/apiStats', verifyToken, async (req, res) => {
    const email = req.userEmail;

    // Check if the user is an admin
    const adminCheckParams = {
        TableName: 'authentication',
        Key: { email },
    };

    try {
        const adminCheckData = await dynamoDB.send(new GetCommand(adminCheckParams));
        const user = adminCheckData.Item;

        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Fetch all endpoint stats
        const statsParams = {
            TableName: 'EndpointStats',
        };

        const statsData = await dynamoDB.send(new ScanCommand(statsParams));
        res.json(statsData.Items); // Return the stats
    } catch (error) {
        console.error('Error fetching API stats:', error);
        res.status(500).json({ error: messages.errors.apiStatsError });
    }
});

app.delete('/deleteProfile', verifyToken, async (req, res) => {
    const email = req.userEmail; // Extract email from the token

    try {
        
        // Delete the user's record from the database
        const deleteParams = {
            TableName: 'authentication',
            Key: { email },
        };

        await dynamoDB.send(new DeleteCommand(deleteParams));

        // Optionally, delete the user's request stats
        const deleteStatsParams = {
            TableName: 'UserRequests',
            Key: { email },
        };

        await dynamoDB.send(new DeleteCommand(deleteStatsParams));

        res.json({ message: messages.success.profileDeleted });
    } catch (error) {
        console.error('Error deleting profile:', error);
        res.status(500).json({ error: messages.errors.deleteProfileError });
    }
});






app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
