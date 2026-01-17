"use strict";

const http = require("node:http");
const https = require("node:https");
const xmlParser = require("./xml-parser");
const xmlUtils = require("./xml-utils");
const sim = require("./simulator");
const digestAuth = require("./service-auth");

const INFORM_PARAMS = [
  "Device.DeviceInfo.SpecVersion",
  "InternetGatewayDevice.DeviceInfo.SpecVersion",
  "Device.DeviceInfo.HardwareVersion",
  "InternetGatewayDevice.DeviceInfo.HardwareVersion",
  "Device.DeviceInfo.SoftwareVersion",
  "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
  "Device.DeviceInfo.ProvisioningCode",
  "InternetGatewayDevice.DeviceInfo.ProvisioningCode",
  "Device.ManagementServer.ParameterKey",
  "InternetGatewayDevice.ManagementServer.ParameterKey",
  "Device.ManagementServer.ConnectionRequestURL",
  "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
  "Device.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
  "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
  "Device.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
  "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress"
];
const downloadTimeoutMs = Number.parseInt(process.env.DOWNLOAD_TIMEOUT, 10) || 30000;
const transferCompleteDelayMs = 500;
const sessionFactoryResetDelayMs = 500;
const validFileTypes = [
  "1 Firmware Upgrade Image",
  "2 Web Content",
  "3 Vendor Configuration File",
  "4 Tone File",
  "5 Ringer File"
];

function inform(device, event, callback) {
  let manufacturer = "";
  if (device["DeviceID.Manufacturer"]) {
    manufacturer = xmlUtils.node(
      "Manufacturer",
      {},
      xmlParser.encodeEntities(device["DeviceID.Manufacturer"][1])
    );
  }
  else if (device["Device.DeviceInfo.Manufacturer"]) {
    manufacturer = xmlUtils.node(
      "Manufacturer",
      {},
      xmlParser.encodeEntities(device["Device.DeviceInfo.Manufacturer"][1])
    );
  } else if (device["InternetGatewayDevice.DeviceInfo.Manufacturer"]) {
    manufacturer = xmlUtils.node(
      "Manufacturer",
      {},
      xmlParser.encodeEntities(device["InternetGatewayDevice.DeviceInfo.Manufacturer"][1])
    );
  }

  let oui = "";
  if (device["DeviceID.OUI"]) {
    oui = xmlUtils.node(
      "OUI",
      {},
      xmlParser.encodeEntities(device["DeviceID.OUI"][1])
    );
  }
  else if (device["Device.DeviceInfo.ManufacturerOUI"]) {
    oui = xmlUtils.node(
      "OUI",
      {},
      xmlParser.encodeEntities(device["Device.DeviceInfo.ManufacturerOUI"][1])
    );
  } else if (device["InternetGatewayDevice.DeviceInfo.ManufacturerOUI"]) {
    oui = xmlUtils.node(
      "OUI",
      {},
      xmlParser.encodeEntities(device["InternetGatewayDevice.DeviceInfo.ManufacturerOUI"][1])
    );
  }

  let productClass = "";
  if (device["DeviceID.ProductClass"]) {
    productClass = xmlUtils.node(
      "ProductClass",
      {},
      xmlParser.encodeEntities(device["DeviceID.ProductClass"][1])
    );
  } else if (device["Device.DeviceInfo.ProductClass"]) {
    productClass = xmlUtils.node(
      "ProductClass",
      {},
      xmlParser.encodeEntities(device["Device.DeviceInfo.ProductClass"][1])
    );
  } else if (device["InternetGatewayDevice.DeviceInfo.ProductClass"]) {
    productClass = xmlUtils.node(
      "ProductClass",
      {},
      xmlParser.encodeEntities(device["InternetGatewayDevice.DeviceInfo.ProductClass"][1])
    );
  }

  let serialNumber = "";
  if (device["DeviceID.SerialNumber"]) {
    serialNumber = xmlUtils.node(
      "SerialNumber",
      {},
      xmlParser.encodeEntities(device["DeviceID.SerialNumber"][1])
    );
  } else if (device["Device.DeviceInfo.SerialNumber"]) {
    serialNumber = xmlUtils.node(
      "SerialNumber",
      {},
      xmlParser.encodeEntities(device["Device.DeviceInfo.SerialNumber"][1])
    );
  } else if (device["InternetGatewayDevice.DeviceInfo.SerialNumber"]) {
    serialNumber = xmlUtils.node(
      "SerialNumber",
      {},
      xmlParser.encodeEntities(device["InternetGatewayDevice.DeviceInfo.SerialNumber"][1])
    );
  }

  let deviceId = xmlUtils.node("DeviceId", {}, [manufacturer, oui, productClass, serialNumber]);
  let eventStruct = "";
  let splitEvents = [];
  if (event !== null) {
    splitEvents = event.split(",");
  }
  else {
    splitEvents = [event];
  }

  splitEvents.forEach(ev => {
    eventStruct += xmlUtils.node(
      "EventStruct",
      {},
      [
        xmlUtils.node("EventCode", {}, ev || "2 PERIODIC"),
        xmlUtils.node("CommandKey")
      ]
    );
  });

  let evnt = xmlUtils.node("Event", {
    "soap-enc:arrayType": "cwmp:EventStruct[1]"
  }, eventStruct);

  let params = [];
  for (let p of INFORM_PARAMS) {
    let param = device[p];
    if (!param)
      continue;

    params.push(xmlUtils.node("ParameterValueStruct", {}, [
      xmlUtils.node("Name", {}, p),
      xmlUtils.node("Value", { "xsi:type": param[2] }, xmlParser.encodeEntities(param[1]))
    ]));
  }

  let parameterList = xmlUtils.node("ParameterList", {
    "soap-enc:arrayType": `cwmp:ParameterValueStruct[${INFORM_PARAMS.length}]`
  }, params);

  let informChildren = [
    deviceId,
    evnt,
    xmlUtils.node("MaxEnvelopes", {}, "1"),
    xmlUtils.node("CurrentTime", {}, new Date().toISOString()),
    xmlUtils.node("RetryCount", {}, "0"),
    parameterList
  ];

  // Check if there are pending transfers to send as TransferComplete (file download or upload or firmware upgrade)
  const pendingTransfer = getPendingTransfers();
  if (pendingTransfer) {
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

    const transferComplete = xmlUtils.node("cwmp:TransferComplete", {}, transferCompleteChildren);
    informChildren.push(transferComplete);

    if (device._pendingReboot) {
      console.log(`⏳ TransferComplete sent, reboot will occur after session ends`);
    }
  }

  let inform = xmlUtils.node("cwmp:Inform", {}, informChildren);

  return callback(inform);
}

const pendingTransfers = [];

function getPendingTransfers() {
  return pendingTransfers.shift();
}


function getSortedPaths(device) {
  if (device._sortedPaths) return device._sortedPaths;
  const ignore = new Set(["DeviceID", "Downloads", "Tags", "Events", "Reboot", "FactoryReset", "VirtualParameters"]);
  device._sortedPaths = Object.keys(device).filter(p => p[0] !== "_" && !ignore.has(p.split(".")[0])).sort();
  return device._sortedPaths;
}


function GetParameterNames(device, request, callback) {
  let parameterNames = getSortedPaths(device);

  let parameterPath, nextLevel;
  for (let c of request.children) {
    switch (c.name) {
      case "ParameterPath":
        parameterPath = c.text;
        break;
      case "NextLevel":
        nextLevel = Boolean(JSON.parse(c.text));
        break;
    }
  }

  let parameterList = [];

  if (nextLevel) {
    for (let p of parameterNames) {
      if (p.startsWith(parameterPath) && p.length > parameterPath.length + 1) {
        let i = p.indexOf(".", parameterPath.length + 1);
        if (i === -1 || i === p.length - 1)
          parameterList.push(p);
      }
    }
  } else {
    for (let p of parameterNames) {
      if (p.startsWith(parameterPath))
        parameterList.push(p);
    }
  }

  let params = [];
  for (let p of parameterList) {
    params.push(
      xmlUtils.node("ParameterInfoStruct", {}, [
        xmlUtils.node("Name", {}, p),
        xmlUtils.node("Writable", {}, String(device[p][0]))
      ])
    );
  }

  let response = xmlUtils.node(
    "cwmp:GetParameterNamesResponse",
    {},
    xmlUtils.node(
      "ParameterList",
      { "soap-enc:arrayType": `cwmp:ParameterInfoStruct[${parameterList.length}]` },
      params
    )
  );

  return callback(response);
}


function GetParameterValues(device, request, callback) {
  let parameterNames = request.children[0].children;

  let params = []
  for (let p of parameterNames) {
    let name = p.text;
    let value = device[name][1];
    let type = device[name][2];
    let valueStruct = xmlUtils.node("ParameterValueStruct", {}, [
      xmlUtils.node("Name", {}, name),
      xmlUtils.node("Value", { "xsi:type": type }, xmlParser.encodeEntities(value))
    ]);
    params.push(valueStruct);
  }

  let response = xmlUtils.node(
    "cwmp:GetParameterValuesResponse",
    {},
    xmlUtils.node(
      "ParameterList",
      { "soap-enc:arrayType": "cwmp:ParameterValueStruct[" + parameterNames.length + "]" },
      params
    )
  );

  return callback(response);
}

function SetParameterValues(device, request, callback) {
  let parameterValues = request.children[0].children;

  for (let p of parameterValues) {
    let name, value;
    for (let c of p.children) {
      switch (c.localName) {
        case "Name":
          name = c.text;
          break;
        case "Value":
          value = c;
          break;
      }
    }

    device[name][1] = xmlParser.decodeEntities(value.text);
    device[name][2] = xmlParser.parseAttrs(value.attrs).find(a => a.localName === "type").value;
  }

  let response = xmlUtils.node("cwmp:SetParameterValuesResponse", {}, xmlUtils.node("Status", {}, "0"));
  return callback(response);
}


function AddObject(device, request, callback) {
  let objectName = request.children[0].text;
  let instanceNumber = 1;

  while (device[`${objectName}${instanceNumber}.`])
    instanceNumber += 1;

  device[`${objectName}${instanceNumber}.`] = [true];

  const defaultValues = {
    "xsd:boolean": "false",
    "xsd:int": "0",
    "xsd:unsignedInt": "0",
    "xsd:dateTime": "0001-01-01T00:00:00Z"
  };

  for (let p of getSortedPaths(device)) {
    if (p.startsWith(objectName) && p.length > objectName.length) {
      let n = `${objectName}${instanceNumber}${p.slice(p.indexOf(".", objectName.length))}`;
      if (!device[n])
        device[n] = [device[p][0], defaultValues[device[p][2]] || "", device[p][2]];
    }
  }

  let response = xmlUtils.node("cwmp:AddObjectResponse", {}, [
    xmlUtils.node("InstanceNumber", {}, String(instanceNumber)),
    xmlUtils.node("Status", {}, "0")
  ]);
  delete device._sortedPaths;
  return callback(response);
}


function DeleteObject(device, request, callback) {
  let objectName = request.children[0].text;

  for (let p in device) {
    if (p.startsWith(objectName))
      delete device[p];
  }

  let response = xmlUtils.node("cwmp:DeleteObjectResponse", {}, xmlUtils.node("Status", {}, "0"));
  delete device._sortedPaths;
  return callback(response);
}


function Download(device, request, callback) {
  const dwInfo = {
    attempts: 0,
    commandKey: null,
    url: null,
    fileType: null,
    username: null,
    password: null
  };

  for (let c of request.children) {
    switch (c.name) {
      case "CommandKey":
        dwInfo.commandKey = xmlParser.decodeEntities(c.text);
        break;
      case "URL":
        dwInfo.url = xmlParser.decodeEntities(c.text);
        break;
      case "FileType":
        dwInfo.fileType = xmlParser.decodeEntities(c.text);
        break;
      case "Username":
        dwInfo.username = xmlParser.decodeEntities(c.text);
        break;
      case "Password":
        dwInfo.password = xmlParser.decodeEntities(c.text);
        break;
    }
  }

  // Check if FileType is missing
  if (!dwInfo.fileType) {
    console.log("❌ Download rejected: FileType parameter is required");
    return callback(createCwmpFault("9003", "Invalid arguments - FileType is required"));
  }
  // Check if FileType is invalid
  if (!validFileTypes.includes(dwInfo.fileType)) {
    console.log(`❌ Download rejected: Invalid FileType '${dwInfo.fileType}'`);
    return callback(createCwmpFault("9003", `Invalid arguments - FileType '${dwInfo.fileType}' not supported`));
  }


  const startTime = new Date();

  // Block concurrent firmware downloads
  if (dwInfo.fileType === "1 Firmware Upgrade Image") {
    if (device._downloadInProgress) {
      console.log("❌ Download rejected: Firmware download already in progress");
      return callback(createCwmpFault("9010", "File transfer already in progress"));
    }
    device._downloadInProgress = true;
  }

  // Validate and start download
  if (dwInfo.url.startsWith("http://")) {
    downloadFile(device, dwInfo.commandKey, startTime, http, dwInfo);
  } else if (dwInfo.url.startsWith("https://")) {
    downloadFile(device, dwInfo.commandKey, startTime, https, dwInfo);
  } else {
    // Invalid URL scheme detected
    if (dwInfo.fileType === "1 Firmware Upgrade Image") {
      device._downloadInProgress = false;
    }
    queueTransferComplete(dwInfo.commandKey, startTime, "9016", "Invalid URL scheme");
    setTimeout(() => {
      sim.startSession("7 TRANSFER COMPLETE");
    }, transferCompleteDelayMs);
  }

  // Send immediate response
  let response = xmlUtils.node("cwmp:DownloadResponse", {}, [
    xmlUtils.node("Status", {}, "1"),
    xmlUtils.node("StartTime", {}, "0001-01-01T00:00:00Z"),
    xmlUtils.node("CompleteTime", {}, "0001-01-01T00:00:00Z")
  ]);

  return callback(response);
}

function createCwmpFault(faultCode, faultString) {
  return xmlUtils.node("cwmp:Fault", {}, [
    xmlUtils.node("FaultCode", {}, String(faultCode)),
    xmlUtils.node("FaultString", {}, xmlParser.encodeEntities(faultString))
  ]);
}

// Helper function to queue transfer result
function queueTransferComplete(commandKey, startTime, faultCode, faultString) {
  // Validate faultCode - must not be empty, null, or undefined
  if (!faultCode || faultCode === "") {
    console.warn("⚠️ Invalid/empty faultCode provided, defaulting to '0' (success)");
    faultCode = "0";
  }

  pendingTransfers.push({
    commandKey: commandKey,
    startTime: startTime,
    faultCode: faultCode,
    faultString: faultString
  });
}

// Download handler with timeout and auth support
function downloadFile(device, commandKey, startTime, urlObj, dwInfo) {
  if (dwInfo.attempts > 5) {
    console.error(`❌ Download failed: Too many redirect/auth attempts`);
    queueTransferComplete(commandKey, startTime, "9010", "Too many attempts");
    return;
  }

  console.log(`📥 Download started: ${dwInfo.url} (Attempt ${dwInfo.attempts + 1})`);

  const urlParsed = new URL(dwInfo.url);
  const options = {
    headers: {}
  };

  if (dwInfo.authHeader) {
    console.log(`🔒 Using auth header: ${dwInfo.authHeader}`);
    options.headers["Authorization"] = dwInfo.authHeader;
  } else if (dwInfo.username && dwInfo.password && dwInfo.attempts === 0) {
    // Try Basic auth initially if no challenge received yet? 
    // Or wait for 401? TR-069 usually expects waiting for 401, but some server might strict.
    // We will wait for 401 unless it's in the URL
  }

  if (dwInfo.cookies && dwInfo.cookies.length > 0) {
    options.headers["Cookie"] = dwInfo.cookies.join("; ");
  }

  const request = urlObj.get(dwInfo.url, options, (res) => {
    // Handle Auth Challenge
    if (res.statusCode === 401) {
      const authHeaderResp = res.headers["www-authenticate"];
      dwInfo.cookies = [];
      // dwInfo.cookies = dwInfo.cookies || [];
      if (res.headers["set-cookie"]) {
        dwInfo.cookies = dwInfo.cookies.concat(res.headers["set-cookie"]);
      }

      if (authHeaderResp) {
        console.log(`🔒 Received 401 Challenge: ${authHeaderResp}`);

        if (authHeaderResp.match(/^Start\s+/i) || authHeaderResp.match(/^Basic\s+/i)) {
          // Basic Auth
          dwInfo.authHeader = "Basic " + Buffer.from(`${dwInfo.username}:${dwInfo.password}`).toString("base64");
          request.destroy();
          dwInfo.attempts++;
          return downloadFile(device, commandKey, startTime, urlObj, dwInfo);
        } else if (authHeaderResp.match(/^Digest\s+/i)) {
          // Digest Auth
          const digestParams = digestAuth.parseDigestHeader(authHeaderResp);
          dwInfo.authHeader = digestAuth.generateDigestAuth(dwInfo.username, dwInfo.password, "GET", urlParsed.pathname + urlParsed.search, digestParams, 1);
          request.destroy();
          dwInfo.attempts++;
          return downloadFile(device, commandKey, startTime, urlObj, dwInfo);
        }
      }
    }

    // Handle Redirects (3xx) if needed? (Not explicitly requested but usually required for robustness)
    // For now sticking to Auth as requested.

    if (res.statusCode !== 200) {
      // If not 200 and not handled above
      console.error(`❌ Download failed with status: ${res.statusCode}`);
      // Read body for debug?
      res.resume();
      // Wait for end?
      queueTransferComplete(commandKey, startTime, "9010", `Server returned code ${res.statusCode}`);
      setTimeout(() => {
        sim.startSession("7 TRANSFER COMPLETE");
      }, transferCompleteDelayMs);
      return;
    }

    let downloadedBytes = 0;

    res.on("data", (chunk) => {
      downloadedBytes += chunk.length;
    });

    res.on("end", () => {
      if (dwInfo.fileType === "1 Firmware Upgrade Image") {
        device._downloadInProgress = false;
      }

      // Clean up request reference
      delete device._activeDownloadRequest;

      console.log(`✅ Download completed successfully (${downloadedBytes} bytes)`);
      queueTransferComplete(commandKey, startTime, "0", "");

      // Wait for TransferComplete session to complete before rebooting
      if (dwInfo.fileType === "1 Firmware Upgrade Image") {
        console.log(`🔄 Firmware upgrade: TransferComplete will be sent, then device will reboot`);

        // Set a flag to trigger reboot after TransferComplete
        device._pendingReboot = true;
        device._firmwareUpgrade = true;

        // Start TransferComplete session
        setTimeout(() => {
          sim.startSession("7 TRANSFER COMPLETE");
        }, transferCompleteDelayMs);
      } else {
        console.log(`📋 Starting TransferComplete session for non-firmware upgrade`);

        // For non-firmware downloads, just send TransferComplete
        setTimeout(() => {
          sim.startSession("7 TRANSFER COMPLETE");
        }, transferCompleteDelayMs);
      }
    });

  }).on("error", (err) => {
    if (dwInfo.fileType === "1 Firmware Upgrade Image") {
      device._downloadInProgress = false;
    }
    delete device._activeDownloadRequest;

    console.error(`❌ Network error: ${err.message}`);
    queueTransferComplete(commandKey, startTime, "9010", err.message);

    setTimeout(() => {
      sim.startSession("7 TRANSFER COMPLETE");
    }, transferCompleteDelayMs);
  });

  // Set timeout (30 seconds)
  request.setTimeout(downloadTimeoutMs, () => {
    request.destroy();
    if (dwInfo.fileType === "1 Firmware Upgrade Image") {
      device._downloadInProgress = false;
    }
    delete device._activeDownloadRequest;

    console.error(`❌ Download timeout after ${downloadTimeoutMs}ms`);
    queueTransferComplete(commandKey, startTime, "9010", "Download timeout");

    setTimeout(() => {
      sim.startSession("7 TRANSFER COMPLETE");
    }, transferCompleteDelayMs);
  });

  // Store request so it can be cancelled by Reboot
  device._activeDownloadRequest = request;
}

function Reboot(device, request, callback) {
  // Cancel active download
  if (device._activeDownloadRequest) {
    console.log("🛑 Cancelling active download due to reboot");
    device._activeDownloadRequest.destroy();
    delete device._activeDownloadRequest;

    if (device._downloadInProgress) {
      device._downloadInProgress = false;

      // Queue TransferComplete with cancellation fault
      queueTransferComplete(
        "cancelled_by_reboot",
        new Date(),
        "9010",
        "Download failure"
      );
    }
  }

  let response = xmlUtils.node("cwmp:RebootResponse", {}, "");
  callback(response);
  let timeout = sim.stopSession(); //stops accepting connections for timeoutseconds

  setTimeout(function () {
    sim.startSession("1 BOOT,M Reboot,4 VALUE CHANGE");
  }, Number.parseInt(timeout, 10) + 10000);
}

function FactoryReset(device, request, callback) {
  let response = xmlUtils.node("cwmp:FactoryResetResponse", {}, "");
  callback(response);
  setTimeout(function () {
    process.kill(process.pid);
  }, sessionFactoryResetDelayMs);
}

exports.inform = inform;
exports.getPendingTransfers = getPendingTransfers;
exports.GetParameterNames = GetParameterNames;
exports.GetParameterValues = GetParameterValues;
exports.SetParameterValues = SetParameterValues;
exports.AddObject = AddObject;
exports.DeleteObject = DeleteObject;
exports.Download = Download;
exports.Reboot = Reboot;
exports.FactoryReset = FactoryReset;