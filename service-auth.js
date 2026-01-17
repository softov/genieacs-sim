"use strict";

const crypto = require("crypto");

function getAuthorizationHeader(device, method, uri) {
  if (!device._username || !device._password) {
    return "";
  }
  if (device._digestParams) {
    device._nonceCount++;
    return generateDigestAuth(
      device._username,
      device._password,
      method ? method : "POST",
      uri ? uri : "/",
      device._digestParams,
      device._nonceCount
    );
  } else {
    return "Basic " + Buffer.from(`${device._username}:${device._password}`).toString("base64");
  }
}

/**
 * Parse WWW-Authenticate header for digest authentication
 * @param {string} header - The WWW-Authenticate header value
 * @returns {object} Parsed digest parameters
 */
function parseDigestHeader(header) {
  const params = {};

  // Remove "Digest " prefix
  const digestStr = header.replace(/^Digest\s+/i, "");

  // Parse key-value pairs
  const regex = /(\w+)=(?:"([^"]+)"|([^\s,]+))/g;
  let match;

  while ((match = regex.exec(digestStr)) !== null) {
    const key = match[1];
    const value = match[2] || match[3];
    params[key] = value;
  }

  return params;
}

/**
 * Generate MD5 hash
 * @param {string} data - Data to hash
 * @returns {string} MD5 hash in hex format
 */
function md5(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

/**
 * Generate digest authentication response
 * @param {string} username - Username
 * @param {string} password - Password
 * @param {string} method - HTTP method (e.g., "POST")
 * @param {string} uri - Request URI
 * @param {object} digestParams - Digest parameters from WWW-Authenticate header
 * @param {number} nc - Nonce count (default: 1)
 * @returns {string} Authorization header value
 */
function generateDigestAuth(username, password, method, uri, digestParams, nc = 1) {
  const realm = digestParams.realm || "";
  const nonce = digestParams.nonce || "";
  const qop = digestParams.qop || "";
  const opaque = digestParams.opaque || "";
  const algorithm = digestParams.algorithm || "MD5";

  // Generate cnonce (client nonce)
  const cnonce = crypto.randomBytes(16).toString("hex");

  // Calculate HA1
  let ha1;
  if (algorithm.toUpperCase() === "MD5-SESS") {
    const ha1Base = md5(`${username}:${realm}:${password}`);
    ha1 = md5(`${ha1Base}:${nonce}:${cnonce}`);
  } else {
    ha1 = md5(`${username}:${realm}:${password}`);
  }

  // Calculate HA2
  const ha2 = md5(`${method}:${uri}`);

  // Calculate response
  let response;
  const ncStr = String(nc).padStart(8, "0");

  if (qop === "auth" || qop === "auth-int") {
    response = md5(`${ha1}:${nonce}:${ncStr}:${cnonce}:${qop}:${ha2}`);
  } else {
    response = md5(`${ha1}:${nonce}:${ha2}`);
  }

  // Build Authorization header
  let authHeader = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;

  if (algorithm) {
    authHeader += `, algorithm=${algorithm}`;
  }

  if (opaque) {
    authHeader += `, opaque="${opaque}"`;
  }

  if (qop) {
    authHeader += `, qop=${qop}, nc=${ncStr}, cnonce="${cnonce}"`;
  }

  return authHeader;
}

module.exports = {
  parseDigestHeader,
  generateDigestAuth,
  md5,
  getAuthorizationHeader
};
