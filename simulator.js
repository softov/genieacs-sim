"use strict";

const net = require("net");
const xmlParser = require("./xml-parser");
const xmlUtils = require("./xml-utils");
const methods = require("./methods");
const digestAuth = require("./service-auth");

const NAMESPACES = {
  "soap-enc": "http://schemas.xmlsoap.org/soap/encoding/",
  "soap-env": "http://schemas.xmlsoap.org/soap/envelope/",
  "xsd": "http://www.w3.org/2001/XMLSchema",
  "xsi": "http://www.w3.org/2001/XMLSchema-instance",
  "cwmp": "urn:dslforum-org:cwmp-1-0"
};

let nextInformTimeout = null;
let pendingInform = false;
let http = null;
let requestOptions = null;
let device = null;
let defaultDeviceValue = null;
let httpAgent = null;
let acceptConnections = true;
let timeout = 10000;

function createSoapDocument(id, body) {
  let headerNode = xmlUtils.node(
    "soap-env:Header",
    {},
    xmlUtils.node("cwmp:ID", { "soap-env:mustUnderstand": 1 }, xmlParser.encodeEntities(id))
  );

  let bodyNode = xmlUtils.node("soap-env:Body", {}, body);
  let namespaces = {};
  for (let prefix in NAMESPACES)
    namespaces[`xmlns:${prefix}`] = NAMESPACES[prefix];

  let env = xmlUtils.node("soap-env:Envelope", namespaces, [headerNode, bodyNode]);

  return `<?xml version="1.0" encoding="UTF-8"?>\n${env}`;
}

function sendRequest(xml, callback) {
  let headers = {};
  let body = xml || "";

  headers["Content-Length"] = body.length;
  headers["Content-Type"] = "text/xml; charset=\"utf-8\"";

  // Use digest auth if available, otherwise fall back to basic auth
  // TODO, change this to one function to be used in file download too
  headers["Authorization"] = digestAuth.getAuthorizationHeader(device, "POST", requestOptions.path);
  if (device._cookie)
    headers["Cookie"] = device._cookie;

  let options = {
    method: "POST",
    headers: headers,
    agent: httpAgent
  };

  Object.assign(options, requestOptions);

  console.log("sendRequest - request create");

  let request = http.request(options, function (response) {
    let chunks = [];
    let bytes = 0;

    response.on("data", function (chunk) {
      chunks.push(chunk);
      return bytes += chunk.length;
    });

    return response.on("end", function () {
      let offset = 0;
      body = Buffer.allocUnsafe(bytes);

      chunks.forEach(function (chunk) {
        chunk.copy(body, offset, 0, chunk.length);
        return offset += chunk.length;
      });

      // Handle 401 Unauthorized - digest auth challenge
      if (response.statusCode === 401) {
        const wwwAuth = response.headers["www-authenticate"];

        if (wwwAuth && wwwAuth.toLowerCase().startsWith("digest")) {
          // Parse digest challenge and retry
          device._digestParams = digestAuth.parseDigestHeader(wwwAuth);
          device._nonceCount = 0;
          console.log(`Simulator received digest auth challenge, retrying with digest authentication`);
          return sendRequest(xml, callback);
        } else {
          throw new Error(
            `Authentication failed with status ${response.statusCode}: ${body}`
          );
        }
      }

      if (Math.floor(response.statusCode / 100) !== 2) {
        throw new Error(
          `Unexpected response Code from ACS ${response.statusCode}: ${body}`
        );
      }

      if (+response.headers["Content-Length"] > 0 || body.length > 0)
        xml = xmlParser.parseXml(body.toString());
      else
        xml = null;

      if (response.headers["set-cookie"])
        device._cookie = response.headers["set-cookie"];

      return callback(xml);
    });
  });

  request.setTimeout(Number.parseInt(timeout, 10) + 30000, function (err) {
    throw new Error("Socket timed out");
  });

  return request.end(body);
}

function startSession(event) { // called automatically after a timeout or when a connection request is received from GENIEACS (PING)
  nextInformTimeout = null;
  pendingInform = false;
  const requestId = Math.random().toString(36).slice(-8);
  let xml = null;
  methods.inform(device, event, function (body) {
    console.log(` startSession event: ${event}`);
    xml = createSoapDocument(requestId, body);
    sendRequest(xml, function (xml) {
      cpeRequest(xml);
    });
  });
}

function createFaultResponse(code, message) {
  let fault = xmlUtils.node(
    "detail",
    {},
    xmlUtils.node("cwmp:Fault", {}, [
      xmlUtils.node("FaultCode", {}, code),
      xmlUtils.node("FaultString", {}, xmlParser.encodeEntities(message))
    ])
  );

  let soapFault = xmlUtils.node("soap-env:Fault", {}, [
    xmlUtils.node("faultcode", {}, "Client"),
    xmlUtils.node("faultstring", {}, "CWMP fault"),
    fault
  ]);

  return soapFault;
}


function cpeRequest(requestXml) {
  // Check for empty response first (session end from ACS)
  if (!requestXml) {
    if (!acceptConnections) {
      console.log(`Session ended while device unavailable`);
      httpAgent.destroy();
      return;
    }
    console.log("✓ Empty response from ACS - session ending normally");
    handleMethod(null);
    return;
  }

  // Now safe to parse the request
  let [requestId,] = getRequestIdAndBody(requestXml);

  // Check if there are pending transfers to send as TransferComplete (file download or upload or firmware upgrade)
  const pendingTransfer = methods.getPendingTransfers();
  if (pendingTransfer) {
    console.log(`cpeRequest pendingTransfer: ${pendingTransfer.commandKey}`);
    // Mark this as a TransferComplete session
    device._transferCompleteSession = true;

    // Start with required elements only
    const transferCompleteChildren = [
      xmlUtils.node("CommandKey", {}, xmlParser.encodeEntities(pendingTransfer.commandKey || "")),
      xmlUtils.node("StartTime", {}, pendingTransfer.startTime.toISOString()),
      xmlUtils.node("CompleteTime", {}, new Date().toISOString())
    ];

    // CONDITIONALLY add FaultStruct only if there's a real fault
    if (pendingTransfer.faultCode && pendingTransfer.faultCode !== "0" && pendingTransfer.faultCode !== "") {
      transferCompleteChildren.push(
        xmlUtils.node("FaultStruct", {}, [
          xmlUtils.node("FaultCode", {}, pendingTransfer.faultCode),
          xmlUtils.node("FaultString", {}, xmlParser.encodeEntities(pendingTransfer.faultString || ""))
        ])
      );
    }

    if (device._pendingReboot) {
      console.log(`⏳ TransferComplete sent, reboot will occur after session ends`);
    }

    const transferComplete = xmlUtils.node("cwmp:TransferComplete", {}, transferCompleteChildren);
    let xml = createSoapDocument(requestId, transferComplete);
    sendRequest(xml, function (xml) {
      handleMethod(xml);
    });
    return;
  }

  // Reject requests if device is unavailable (rebooting, etc.)
  if (!acceptConnections) {
    console.log(`Simulator is not accepting connections, waiting for ${timeout} milliseconds`);
    // Respond with a TR-069 Fault code (e.g., 9002 "Internal error")
    let faultBody = createFaultResponse(9002, "Device not ready to accept requests");
    let xml = createSoapDocument(requestId, faultBody);
    sendRequest(xml, function () {
      // Session should end
      httpAgent.destroy();
    });
    return;
  }

  // Normal flow - device is accepting connections
  sendRequest(null, function (xml) {
    handleMethod(xml);
  });
}


function handleMethod(xml) {
  if (!xml) {
    httpAgent.destroy();

    // Check if firmware reboot is pending AND we're ending a TransferComplete session
    if (device._pendingReboot && device._firmwareUpgrade && device._transferCompleteSession) {
      console.log(`🔄 TransferComplete session ended, initiating reboot for firmware upgrade`);
      delete device._pendingReboot;
      delete device._firmwareUpgrade;
      delete device._transferCompleteSession;

      const rebootTimeout = stopSession();
      setTimeout(() => {
        console.log(`🚀 Device booting after firmware upgrade`);

        // Update software version to simulate firmware change
        updateParameter("Device.DeviceInfo.SoftwareVersion", "2.0.0-upgraded");
        updateParameter("InternetGatewayDevice.DeviceInfo.SoftwareVersion", "2.0.0-upgraded");

        startSession("1 BOOT,M Download,4 VALUE CHANGE");
      }, rebootTimeout);
      return;
    }

    // Clear TransferComplete session flag if set (for non-firmware transfers)
    if (device._transferCompleteSession) {
      delete device._transferCompleteSession;
    }

    // Check for regular reboot (non-firmware)
    if (device._pendingReboot) {
      console.log(`🔄 Session ended, rebooting device`);
      delete device._pendingReboot;

      const rebootTimeout = stopSession();
      setTimeout(() => {
        startSession("1 BOOT,M Reboot");
      }, rebootTimeout);
      return;
    }

    let informInterval = 10;
    if (device["Device.ManagementServer.PeriodicInformInterval"])
      informInterval = Number.parseInt(device["Device.ManagementServer.PeriodicInformInterval"][1], 10);
    else if (device["InternetGatewayDevice.ManagementServer.PeriodicInformInterval"])
      informInterval = Number.parseInt(device["InternetGatewayDevice.ManagementServer.PeriodicInformInterval"][1], 10);

    nextInformTimeout = setTimeout(function () {
      startSession(null); //3 SCHEDULED
    }, pendingInform ? 0 : 1000 * informInterval);

    return;
  }

  let [requestId, bodyElement] = getRequestIdAndBody(xml);

  let requestElement;
  for (let c of bodyElement.children) {
    if (c.name.startsWith("cwmp:")) {
      requestElement = c;
      break;
    }
  }
  let method = methods[requestElement.localName];

  if (!method) {
    let body = createFaultResponse(9000, "Method not supported");
    let xml = createSoapDocument(requestId, body);
    sendRequest(xml, function (xml) {
      handleMethod(xml);
    });
    return;
  }


  method(device, requestElement, function (body) {
    let xml = createSoapDocument(requestId, body);
    sendRequest(xml, function (xml) {
      handleMethod(xml);
    });
  });
}

function listenForConnectionRequests(serialNumber, acsUrlOptions, callback) {
  let ip, port;
  // Start a dummy socket to get the used local ip
  let socket = net.createConnection({
    port: acsUrlOptions.port,
    host: acsUrlOptions.hostname,
    family: 4
  })
    .on("error", callback)
    .on("connect", () => {
      ip = socket.address().address;
      port = socket.address().port + 1;
      socket.end();
    })
    .on("close", () => {
      const connectionRequestUrl = `http://${ip}:${port}/`;
      const httpServer = http.createServer((_req, res) => {
        if (!acceptConnections) {
          console.log(`Simulator is rebooting, refusing connection request.`);
          _req.socket.destroy(); // Immediately close the connection
          return;
        }
        console.log(`Simulator ${serialNumber} got connection request`);
        res.end();
        // A session is ongoing when nextInformTimeout === null
        if (nextInformTimeout === null) pendingInform = true;
        else {
          clearTimeout(nextInformTimeout);
          nextInformTimeout = setTimeout(function () {
            startSession("6 CONNECTION REQUEST");
          }, 0);
        }
      });

      httpServer.listen(port, ip, err => {
        if (err) return callback(err);
        console.log(
          `Simulator ${serialNumber} listening for connection requests on ${connectionRequestUrl}`
        );
        if (acceptConnections) {
          return callback(null, connectionRequestUrl);
        }
      });
    });
}

function start(dataModel, serialNumber, macAddress, acsUrl, defaultTimeout) {
  timeout = defaultTimeout;
  device = dataModel;
  defaultDeviceValue = dataModel;

  // Clean up any temporary state flags from previous runs
  // These flags are used for async operations and should not persist across restarts
  delete device._pendingReboot;
  delete device._firmwareUpgrade;
  delete device._transferCompleteSession;
  delete device._downloadInProgress;
  device._activeDownloadRequest = null;
  device._digestParams = null;
  device._nonceCount = 0;
  device._cookie = null;

  if (device["DeviceID.SerialNumber"])
    device["DeviceID.SerialNumber"][1] = serialNumber;
  if (device["Device.DeviceInfo.SerialNumber"])
    device["Device.DeviceInfo.SerialNumber"][1] = serialNumber;
  if (device["InternetGatewayDevice.DeviceInfo.SerialNumber"])
    device["InternetGatewayDevice.DeviceInfo.SerialNumber"][1] = serialNumber;

  if (device["InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"])
    device["InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"][1] = macAddress;
  if (device["Device.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"])
    device["Device.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress"][1] = macAddress;

  device._username = "usertest";
  device._password = "passtest";
  if (device["Device.ManagementServer.Username"]) {
    device._username = device["Device.ManagementServer.Username"][1];
    device._password = device["Device.ManagementServer.Password"][1];
  } else if (device["InternetGatewayDevice.ManagementServer.Username"]) {
    device._username = device["InternetGatewayDevice.ManagementServer.Username"][1];
    device._password = device["InternetGatewayDevice.ManagementServer.Password"][1];
  }

  // requestOptions = require("url").parse(acsUrl);
  const parsedUrl = new URL(acsUrl);
  requestOptions = {
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname,
    port: parsedUrl.port,
    // path: parsedUrl.pathname,
    path: parsedUrl.pathname + parsedUrl.search,
    href: parsedUrl.href
  };
  // console.log('requestOptions', requestOptions);
  // console.log('requestOptions', require("url").parse(acsUrl));
  http = requestOptions.protocol.slice(0, -1) == 'http' ? require('http') : require('https');

  httpAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });

  listenForConnectionRequests(serialNumber, requestOptions, (err, connectionRequestUrl) => {
    if (err) throw err;
    if (device["InternetGatewayDevice.ManagementServer.ConnectionRequestURL"]) {
      device["InternetGatewayDevice.ManagementServer.ConnectionRequestURL"][1] = connectionRequestUrl;
    } else if (device["Device.ManagementServer.ConnectionRequestURL"]) {
      device["Device.ManagementServer.ConnectionRequestURL"][1] = connectionRequestUrl;
    }
    startSession("1 BOOT");
  });
}

function stopSession() {
  acceptConnections = false;
  console.log(`Simulator Stopped listening for requests for ${timeout}`);
  setTimeout(() => {
    acceptConnections = true;
    console.log(`Simulator resumed listening.`);
  }, timeout);
  return timeout;
}

function updateParameter(parameter, value) {
  // Check if device is initialized
  if (!device) {
    console.error(`❌ Cannot update parameter: device not initialized`);
    return;
  }

  if (device[parameter]) {
    device[parameter][1] = value;
    console.log(`📝 Updated ${parameter} = ${value}`);
  } else {
    console.warn(`⚠️ Parameter ${parameter} does not exist in device model`);
  }
}

function getRequestIdAndBody(xml) {
  let headerElement, bodyElement;
  let envelope = xml.children[0];
  for (const c of envelope.children) {
    switch (c.localName) {
      case "Header":
        headerElement = c;
        break;
      case "Body":
        bodyElement = c;
        break;
    }
  }

  let requestId;
  for (let c of headerElement.children) {
    if (c.localName === "ID") {
      requestId = xmlParser.decodeEntities(c.text);
      break;
    }
  }
  return [requestId, bodyElement];
}

exports.start = start;
exports.startSession = startSession;
exports.stopSession = stopSession;
exports.updateParameter = updateParameter;