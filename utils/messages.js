const messages = {
    errors: {
        noToken: 'No token provided',
        unauthorized: 'Unauthorized',
        emailExists: 'Email already exists',
        invalidCredentials: 'Invalid email or password',
        serverError: 'Internal server error',
        accessDenied: 'Access denied',
        adviceError: 'Error retrieving advice',
        deleteProfileError: 'Failed to delete profile.',
        requestCountError: 'Error retrieving request count',
        userRequestError: 'Error retrieving user request data',
        apiStatsError: 'Error retrieving API stats',
        updateRequestError: 'Failed to update request count.',
    },
    success: {
        userRegistered: 'User registered successfully',
        profileDeleted: 'Profile deleted successfully.',
        requestCountUpdated: 'Request count updated successfully.',
    },
    warnings: {
        freeLimitExceeded: 'You have exceeded 20 free requests. Further usage may require additional permissions.',
    },
};

module.exports = messages;
