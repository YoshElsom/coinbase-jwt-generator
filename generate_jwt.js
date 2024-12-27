// generate_jwt.js

const { sign } = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * === Configuration Section ===
 * 
 * Replace the placeholders below with your actual Coinbase API details.
 */

// Your Coinbase API key name (format: 'organizations/{org_id}/apiKeys/{key_id}')
const keyName = 'organizations/ed176d77-4864-487e-a402-a9f4fc13e7d2/apiKeys/9d695fa7-185e-4bd7-9142-3b00e1b6baea';

// Your ECDSA Private Key (including the BEGIN and END lines)
// Ensure that the newlines (\n) are preserved.
// It's recommended to store your private key securely and avoid sharing it.
const privateKey = `-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIMPlS+v5lWX2PS/jt7L9Uu92LSCQLrfpnXJ+9o0osVXRoAoGCCqGSM49\nAwEHoUQDQgAE1wZ3gVV22flC+vJSQSOeh1lHrDSzhHWarA+K5fMPJh2vXjRJQSoq\nCLfzU96TAqKTgS9ttgQOp9vi6isIg2CViQ==\n-----END EC PRIVATE KEY-----\n`;

/**
 * === JWT Generation Function ===
 * 
 * Generates a JSON Web Token (JWT) for authenticating with Coinbase's API.
 * 
 * @param {string} method - HTTP method (e.g., 'GET', 'POST').
 * @param {string} path - API endpoint path (e.g., '/v2/accounts').
 * @returns {string} - Signed JWT.
 */
function generateCoinbaseJWT(method, path) {
  const iat = Math.floor(Date.now() / 1000); // Current time in seconds
  const exp = iat + 120; // JWT expiration time (2 minutes from now)
  const nonce = crypto.randomBytes(16).toString('hex'); // 16-byte random nonce

  // Construct the URI as per Coinbase's requirements
  const uri = `${method} api.coinbase.com${path}`;

  // Define the JWT payload
  const payload = {
    iss: 'cdp',       // Issuer
    nbf: iat,         // Not Before
    exp: exp,         // Expiration Time
    sub: keyName,     // Subject (your API key name)
    uri: uri,         // URI (method and path)
  };

  // Sign the JWT using ES256 (ECDSA with P-256 and SHA-256)
  const token = sign(payload, privateKey, {
    algorithm: 'ES256',
    header: {
      kid: keyName,    // Key ID
      nonce: nonce     // Unique nonce for this JWT
    }
  });

  return token;
}

/**
 * === Command-Line Interface ===
 * 
 * Allows you to generate a JWT by specifying the HTTP method and API path.
 * 
 * Usage:
 *   node generate_jwt.js [METHOD] [PATH]
 * 
 * Examples:
 *   node generate_jwt.js GET /v2/accounts
 *   node generate_jwt.js GET /v2/accounts/55c1dd27-a83a-5679-b165-587d6ca3d507
 */

// Extract command-line arguments
const args = process.argv.slice(2);
const method = args[0] || 'GET';            // Default to 'GET' if not provided
const path = args[1] || '/v2/accounts';      // Default to '/v2/accounts' if not provided

// Generate the JWT
const jwt = generateCoinbaseJWT(method, path);

// Output the JWT to the console
console.log(jwt);
