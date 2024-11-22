// Validation for registration inputs
const validateRegistration = (req, res, next) => {
    const { name, email, password } = req.body;

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }

    // Password validation (minimum 6 characters)
    if (!password || password.length < 3) {
        return res.status(400).json({ error: 'Password must be at least 3 characters long.' });
    }

    // Name validation (must not be empty)
    if (!name || name.trim() === '') {
        return res.status(400).json({ error: 'Name is required.' });
    }

    next();
};

// Validation for login inputs
const validateLogin = (req, res, next) => {
    const { email, password } = req.body;

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }

    // Password validation
    if (!password || password.length < 3) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    next();
};

// Validation for advice inputs
const validateAdviceInputs = (req, res, next) => {
    const { age, name, behavior } = req.body;

    // Age validation (positive number)
    if (!age || isNaN(age) || age <= 0) {
        return res.status(400).json({ error: 'Age must be a positive number.' });
    }

    // Name validation
    if (!name || name.trim() === '') {
        return res.status(400).json({ error: 'Name is required.' });
    }

    // Behavior validation
    if (!behavior || behavior.trim() === '') {
        return res.status(400).json({ error: 'Behavior is required.' });
    }

    next();
};

// Validation for request count updates
const validateUpdateRequestCount = (req, res, next) => {
    const { email, requestCount } = req.body;

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }

    // Request count validation (positive integer)
    if (!Number.isInteger(requestCount) || requestCount < 0) {
        return res.status(400).json({ error: 'Request count must be a non-negative integer.' });
    }

    next();
};

module.exports = {
    validateRegistration,
    validateLogin,
    validateAdviceInputs,
    validateUpdateRequestCount,
};
