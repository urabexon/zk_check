const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

const VERIFICATION_KEY_PATH = path.join(__dirname, '../build/verification_key.json');

let verificationKey = null;

try {
    const vkeyData = fs.readFileSync(VERIFICATION_KEY_PATH, 'utf8');
    verificationKey = JSON.parse(vkeyData);
    console.log('Verification key loaded successfully');
} catch (error) {
    console.error('Failed to load verification key:', error);
    process.exit(1);
}

app.post('/authenticate', async (req, res) => {
    try {
        const { proof, publicSignals } = req.body;
        
        if (!proof || !publicSignals) {
            return res.status(400).json({
                success: false,
                message: 'Proof and public signals are required'
            });
        }

        console.log('Received authentication request');
        console.log('Public signals:', publicSignals);

        const isValid = await snarkjs.groth16.verify(
            verificationKey,
            publicSignals,
            proof
        );

        console.log('Proof verification result:', isValid);

        if (isValid && publicSignals[0] === '1') {
            res.json({
                success: true,
                message: 'Authentication successful! You proved knowledge of the password without revealing it.',
                authenticated: true
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Authentication failed. Invalid proof.',
                authenticated: false
            });
        }
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during authentication',
            error: error.message
        });
    }
});

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Zero Knowledge Authentication Server is running',
        timestamp: new Date().toISOString()
    });
});

app.get('/verification-key', (req, res) => {
    if (verificationKey) {
        res.json(verificationKey);
    } else {
        res.status(500).json({
            success: false,
            message: 'Verification key not available'
        });
    }
});

app.listen(PORT, () => {
    console.log(`🔒 ZK Authentication Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`Authentication endpoint: http://localhost:${PORT}/authenticate`);
});