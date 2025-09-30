const axios = require("axios");
const csv = require('csv-parser');
const fs = require("fs");
const csvWriter = require('csv-write-stream');

const writer = csvWriter({
    headers: ["referenceId", "title", "cardNumber", "adjustmentType", "amount", "merchantId", "remarks", "basePoints", "bonusPoints", "Status", "Error Message", "Raw Error"]
});
writer.pipe(fs.createWriteStream(`GrantPointResult-${process.argv[2]}.csv`, { flags: 'a' }));

async function getAccessToken() {
  const loginURL = 'https://api.prod.setel.my/api/iam/setel-external-services/auth/login';
  // const loginURL = 'https://api.staging2.setel.my/api/iam/setel-external-services/auth/login';
  const payload = {
    identifier: "enterprise-ops",
    password: "6GA-RYGj)*{^]Usr"
  }
  const response = await axios.post(loginURL, payload, {
    headers: {
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
    }
  })
  const token = response.data.accessToken;
  console.log("********** TOKEN **********\n",token);
  return token;
}

async function grantMesra() {
  try {
    const accessToken = await getAccessToken();
    const mesraUrl = `https://api.prod.setel.my/api/loyalty/admin/points/adjustment/autoApprove`;
    // const mesraUrl = `https://api.staging2.setel.my/api/loyalty/admin/points/adjustment/autoApprove`;
    const grantPointRequests = [];

    fs.createReadStream(`${process.argv[2]}.csv`)
    .pipe(csv())
    .on('data', (data) => {
      // Convert string values to appropriate types
      data.amount = Number(data.amount);
      data.basePoints = Number(data.basePoints);
      data.bonusPoints = Number(data.bonusPoints);
      grantPointRequests.push(data);
    })
    .on('end', async () => {
      for (const request of grantPointRequests) {
        console.log(request);
        try {
          // Create the new payload structure with grantMembership
          const payload = {
            title: request.title,
            cardNumber: request.cardNumber,
            adjustmentType: request.adjustmentType,
            amount: request.amount,
            grantMembership: {
              basePoint: request.basePoints,
              bonusPoint: request.bonusPoints
            }
          };

          const result = await axios.post(mesraUrl, payload, {
            headers: {
              "Content-Type": "application/json",
              "access-token": accessToken
            }
          })
          console.log(result.status + " Successfully granted mesra points!");
          writer.write([payload.referenceId, request.title, request.cardNumber, request.adjustmentType, request.amount, "default-merchant-id", request.remarks, request.basePoints, request.bonusPoints, result.status, "N/A", "N/A"]);
        } catch (err) {
          const responseData = err?.response?.data ?? {status: 'N/A', message: 'N/A'};
          console.log("ERROR RESPONSE "+ JSON.stringify(responseData));
          writer.write([`REF-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, request.title, request.cardNumber, request.adjustmentType, request.amount, "default-merchant-id", request.remarks, request.basePoints, request.bonusPoints, responseData.status, responseData.message, JSON.stringify(responseData)]);
        }
      }
      writer.end();
      console.log("********** End **********\n")
    });
  } catch (err) {
    console.log("********** Error **********\n");
    console.log(err)
    console.log(err.response)
    console.log("********** Error **********\n");
  }
}
grantMesra();
