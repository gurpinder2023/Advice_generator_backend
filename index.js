const express = require('express');
const app = express();
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, UpdateCommand, ScanCommand } = require('@aws-sdk/lib-dynamodb');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const port = 3000;
require('dotenv').config();

app.use(bodyParser.json());

// Enable CORS for any origin (or specify allowed origins)
app.use(cors({
    origin: 'https://advice-generator-frontend-vp3q.vercel.app', // Specify your frontend URL
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
    if (!token) return res.status(403).send({ error: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'Unauthorized' });
        req.userEmail = decoded.email; // Store the user's email in the request object for later use
        next();
    });
};

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
             response.warning = "You have exceeded 20 free requests. Further usage may require additional permissions.";
         }
 
         res.json(response); // Return the request count and the warning if applicable // Return the request count
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error retrieving request count' });
    }
});


app.post('/register', async (req, res) => {
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
            return res.status(400).json({ error: 'Email already exists' });
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

        await dynamoDB.send(new UpdateCommand(params));

        res.status(201).json({ message: 'User registered successfully' });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const params = {
        TableName: 'authentication',
        Key: { email },
    };

    try {
        const data = await dynamoDB.send(new GetCommand(params));
        const user = data.Item;

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Compare the provided password with the hashed password in the database
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate a JWT
        const token = jwt.sign({ email: user.email, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

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
        res.status(500).json({ error: 'Error retrieving user request data' });
    }
});

// New endpoint to get health advice
app.post('/getAdvice', verifyToken, async (req, res) => {
    const { age, name, behavior } = req.body;
    const email = req.userEmail; // Get the user's email from the request object

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
        console.error('Error getting advice from Flask server:', error);
        res.status(500).json({ error: 'Error retrieving advice' }); // Handle error
    }
});



app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
