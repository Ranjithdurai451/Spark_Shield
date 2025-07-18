import express from "express";
import axios from "axios";
import multer from "multer";
import FormData from "form-data";
import crypto from "crypto";
import * as fs from "fs";
import simpleGit from "simple-git";
import dotenv from "dotenv";
import cors from "cors";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { analyzeFile, checkGitHubRepo, getAllFiles } from "./lib/utils.js";
import { arch } from "os";
// 🔹 Load environment variables
dotenv.config();

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_BASE_URL || "*",
  }),
);
const PORT = 8080;

// Initialize Gemini with API Key
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

// Middleware
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage() });

const VIRUSTOTAL_API = "https://www.virustotal.com/api/v3";
const VT_HEADERS = { "x-apikey": process.env.VIRUSTOTAL_API_KEY };

// Polling configuration
const MAX_POLLING_ATTEMPTS = 30;
const POLLING_INTERVAL = 15000;

// Helper function to poll for completed results
async function pollForResults(scan_id) {
  let analysisComplete = false;
  let attempts = 0;
  let reportResponse;

  while (!analysisComplete && attempts < MAX_POLLING_ATTEMPTS) {
    attempts++;
    console.log(
      `🔄 Polling attempt ${attempts}/${MAX_POLLING_ATTEMPTS} for scan ID: ${scan_id}`,
    );

    reportResponse = await axios.get(`${VIRUSTOTAL_API}/analyses/${scan_id}`, {
      headers: VT_HEADERS,
    });

    if (reportResponse.data.data.attributes.status === "completed") {
      analysisComplete = true;
      console.log(`✅ Analysis completed after ${attempts} attempts`);
    } else {
      console.log(
        `⏳ Analysis status: ${
          reportResponse.data.data.attributes.status
        }. Waiting ${POLLING_INTERVAL / 1000} seconds...`,
      );
      await new Promise((resolve) => setTimeout(resolve, POLLING_INTERVAL));
    }
  }

  return {
    response: reportResponse,
    complete: analysisComplete,
    attempts: attempts,
  };
}
app.get("/", async (req, res) => {
  res.json({ message: "SparkShield Api is running" });
});
// 1️⃣ **Scan a URL with polling for completion**
app.get("/scan/url", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "URL is required" });

  console.log(`📌 Scanning URL: ${url}`);

  try {
    // Submit URL for scanning
    const scanResponse = await axios.post(
      `${VIRUSTOTAL_API}/urls`,
      new URLSearchParams({ url }),
      { headers: VT_HEADERS },
    );

    const scan_id = scanResponse.data.data.id;
    console.log(`✅ URL scan initiated with ID: ${scan_id}`);

    // Poll for results
    const pollResult = await pollForResults(scan_id);

    if (!pollResult.complete) {
      console.warn(
        `⚠️ Analysis did not complete after ${pollResult.attempts} attempts`,
      );
      return res.status(202).json({
        status: "pending",
        message: "Analysis is still in progress. Please try again later.",
        scan_id: scan_id,
      });
    }

    console.log(`✅ Retrieved complete report for scan ID: ${scan_id}`);

    // Check if we have results in the response
    if (
      Object.keys(pollResult.response.data.data.attributes.results).length === 0
    ) {
      console.warn("⚠️ Empty results in completed analysis");
    }

    res.json(pollResult.response.data);
  } catch (error) {
    console.error(`❌ Error scanning URL: ${url}`, error.message);
    res.status(500).json({
      error: "Error scanning URL",
      details: error.response?.data || error.message,
    });
  }
});

// 2️⃣ **Scan a File with polling for completion**
app.post("/scan/file", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      console.error("❌ No file provided in request");
      return res.status(400).json({ error: "No file provided" });
    }

    console.log(`📌 Scanning file: ${req.file.originalname}`);

    const formData = new FormData();
    formData.append("file", req.file.buffer, req.file.originalname);

    const scanResponse = await axios.post(`${VIRUSTOTAL_API}/files`, formData, {
      headers: { ...VT_HEADERS, ...formData.getHeaders() },
    });

    const scan_id = scanResponse.data.data.id;
    console.log(`✅ File scan initiated with ID: ${scan_id}`);

    // Poll for results
    const pollResult = await pollForResults(scan_id);

    if (!pollResult.complete) {
      console.warn(
        `⚠️ Analysis did not complete after ${pollResult.attempts} attempts`,
      );
      return res.status(202).json({
        status: "pending",
        message: "Analysis is still in progress. Please try again later.",
        scan_id: scan_id,
      });
    }

    console.log(`✅ Retrieved complete report for scan ID: ${scan_id}`);
    res.json(pollResult.response.data);
  } catch (error) {
    console.error(`❌ Error scanning file:`, error.message);
    res.status(500).json({
      error: "Error scanning file",
      details: error.response?.data || error.message,
    });
  }
});

// 3️⃣ **Scan a Domain or IP**
app.get("/scan/domain/:value", async (req, res) => {
  try {
    const { value } = req.params;
    console.log(`📌 Getting domain report for: ${value}`);

    const response = await axios.get(`${VIRUSTOTAL_API}/domains/${value}`, {
      headers: VT_HEADERS,
    });

    console.log(`✅ Successfully retrieved domain report for: ${value}`);
    res.json(response.data);
  } catch (error) {
    console.error(
      `❌ Error fetching domain scan report for ${req.params.value}:`,
      error.message,
    );
    res.status(500).json({
      error: "Error fetching domain scan report",
      details: error.response?.data || error.message,
    });
  }
});

app.get("/scan/ip/:value", async (req, res) => {
  try {
    const { value } = req.params;
    console.log(`📌 Getting IP report for: ${value}`);

    const response = await axios.get(
      `${VIRUSTOTAL_API}/ip_addresses/${value}`,
      {
        headers: VT_HEADERS,
      },
    );

    console.log(`✅ Successfully retrieved IP report for: ${value}`);
    res.json(response.data);
  } catch (error) {
    console.error(
      `❌ Error fetching IP scan report for ${req.params.value}:`,
      error.message,
    );
    res.status(500).json({
      error: "Error fetching IP scan report",
      details: error.response?.data || error.message,
    });
  }
});

// 4️⃣ **Fetch Scan Report with polling if necessary**
app.get("/report/:scan_id", async (req, res) => {
  try {
    const { scan_id } = req.params;
    console.log(`📌 Retrieving report for scan ID: ${scan_id}`);

    // Get initial report
    const response = await axios.get(`${VIRUSTOTAL_API}/analyses/${scan_id}`, {
      headers: VT_HEADERS,
    });

    // Check if report is completed, if not, poll for completion
    if (response.data.data.attributes.status !== "completed") {
      console.log(
        `⏳ Report not yet completed. Status: ${response.data.data.attributes.status}`,
      );
      console.log(`🔄 Starting polling for scan ID: ${scan_id}`);

      const pollResult = await pollForResults(scan_id);

      if (!pollResult.complete) {
        console.warn(
          `⚠️ Analysis did not complete after ${pollResult.attempts} attempts`,
        );
        return res.status(202).json({
          status: "pending",
          message: "Analysis is still in progress. Please try again later.",
          scan_id: scan_id,
        });
      }

      console.log(
        `✅ Successfully retrieved complete report for scan ID: ${scan_id}`,
      );
      return res.json(pollResult.response.data);
    }

    console.log(`✅ Successfully retrieved report for scan ID: ${scan_id}`);
    res.json(response.data);
  } catch (error) {
    console.error(
      `❌ Error retrieving report for scan ID ${req.params.scan_id}:`,
      error.message,
    );
    res.status(500).json({ error: error.response?.data || error.message });
  }
});

// 5️⃣ **Get scan status (new endpoint)**
app.get("/scan/status/:scan_id", async (req, res) => {
  try {
    const { scan_id } = req.params;
    console.log(`📌 Checking status for scan ID: ${scan_id}`);

    const response = await axios.get(`${VIRUSTOTAL_API}/analyses/${scan_id}`, {
      headers: VT_HEADERS,
    });

    const status = response.data.data.attributes.status;
    console.log(`✅ Retrieved status for scan ID: ${scan_id}: ${status}`);

    res.json({
      scan_id,
      status,
      data: response.data,
    });
  } catch (error) {
    console.error(
      `❌ Error checking scan status for ${req.params.scan_id}:`,
      error.message,
    );
    res.status(500).json({ error: error.response?.data || error.message });
  }
});

// 6️⃣ **Remediation Guidance**
app.get("/remediation", async (req, res) => {
  try {
    const { threat_type } = req.query;
    if (!threat_type) {
      console.error("❌ No threat type provided in request");
      return res.status(400).json({ error: "Threat type is required" });
    }

    console.log(`📌 Getting remediation for threat type: ${threat_type}`);
    const prompt = `Provide remediation steps for ${threat_type} detected by VirusTotal.`;

    const geminiResponse = await model.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
    });

    const responseText = geminiResponse.response.text();

    console.log(
      `✅ Successfully retrieved remediation for threat type: ${threat_type}`,
    );
    res.json({ remediation_steps: responseText });
  } catch (error) {
    console.error(`❌ Error getting remediation guidance:`, error.message);
    res.status(500).json({ error: error.response?.data || error.message });
  }
});

// 7️⃣ **Scan GitHub Repository**
app.get("/scan-repo", async (req, res) => {
  const { repoUrl } = req.query;
  if (!repoUrl) {
    console.error("❌ No repository URL provided");
    return res
      .status(400)
      .json({ status: "❌ Error", message: "Repository URL required" });
  }

  console.log(`📌 Starting scan for repository: ${repoUrl}`);
  const repoPath = `repos/${crypto.randomUUID()}`;
  try {
    // 🛡️ Step 1: Clone the Repository
    console.log(`📥 Cloning repository: ${repoUrl} to ${repoPath}`);
    await simpleGit().clone(repoUrl, repoPath);
    console.log(`✅ Repository cloned successfully`);

    // 🛡️ Step 2: Scan All Script Files
    const scanResults = [];
    console.log(`🔍 Scanning repository at: ${repoPath}`);
    const files = getAllFiles(repoPath);
    console.log(`📋 Found ${files.length} files to analyze`);

    for (const file of files) {
      if (
        file.endsWith(".js") ||
        file.endsWith(".py") ||
        file.endsWith(".sh")
      ) {
        console.log(`🔍 Analyzing file: ${file}`);
        const result = await analyzeFile(file);
        scanResults.push(result);
        console.log(`✅ Analysis complete for: ${file}`);
      }
    }

    // 🛡️ Step 3: Check Repository Trust
    let trustCheck = { status: "Unknown" };

    try {
      console.log(`🛡️ Checking GitHub trust for repository: ${repoUrl}`);
      trustCheck = await checkGitHubRepo(repoUrl);
      console.log(
        `✅ GitHub trust check completed with status: ${trustCheck.status}`,
      );
    } catch (error) {
      console.error(`❌ Error checking GitHub trust:`, error.message);
    }

    // Cleanup
    console.log(`🧹 Cleaning up temporary directory: ${repoPath}`);
    fs.rmSync(repoPath, { recursive: true, force: true });
    console.log(`✅ Cleanup complete`);

    console.log(`✅ Repository scan completed successfully`);
    res.json({ trust: trustCheck, results: scanResults });
  } catch (error) {
    console.error(`❌ Error scanning repository:`, error.message);
    try {
      // Attempt cleanup even if there was an error
      console.log(
        `🧹 Cleaning up temporary directory after error: ${repoPath}`,
      );
      fs.rmSync(repoPath, { recursive: true, force: true });
    } catch (cleanupError) {
      console.error(`❌ Error during cleanup:`, cleanupError.message);
    }
    res
      .status(500)
      .json({ status: "❌ Error", message: "Failed to scan repository" });
  }
});

// 8️⃣ **Fake Website Detection Endpoint**
// app.post('/detect-clone', upload.single('image'), async (req, res) => {
//   console.log(`📌 Starting fake website detection from uploaded image`);
//   try {
//     if (!req.file) {
//       console.error(`❌ No image uploaded for fake website detection`);
//       return res.status(400).json({ error: 'No image uploaded' });
//     }

//     // Convert image to Base64 for Gemini input
//     const base64Image = req.file.buffer.toString('base64');
//     console.log(
//       `✅ Image converted to Base64. Size: ${base64Image.length} characters`
//     );
//     console.log(`🔍 Sending image to Gemini AI for analysis...`);

//     // Send to Gemini Flash 2.0 for evaluation
//     const result = await model.generateContent({
//       contents: [
//         {
//           role: 'user',
//           parts: [
//             {
//               text: `Analyze this website screenshot and determine if it's a fake or a cloned site.
//               Provide the following structured data in JSON format:
//               - legitimacy_score (0-100, with 100 being most legit)
//               - red_flags (list of any suspicious elements)
//               - verified_elements (list of elements that match a real site)
//               - phishing_risk_level (Low, Medium, High)
//               - suggested_actions (practical tips for the user)
//               - full_analysis (detailed explanation of findings)`,
//             },
//             { inlineData: { mimeType: req.file.mimetype, data: base64Image } },
//           ],
//         },
//       ],
//     });
//     const responseText = result.response.text();
//     console.log('Gemini Response:', responseText);

//     // Remove any Markdown code block formatting (json ... )
//     const cleanedResponse = responseText.replace(/json|/g, '').trim();
//     const analysis = JSON.parse(cleanedResponse);
//     console.log(`✅ Received analysis from Gemini AI`);
//     return res.json(analysis);
//   } catch (error) {
//     console.error(`❌ Error in fake website detection:`, error.message);
//     return res.status(500).json({ error: 'Internal server error' });
//   }
// });
// Fake Website Detection Endpoint
app.post("/detect-clone", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image uploaded" });
    }

    // Convert image to Base64 for Gemini input
    const base64Image = req.file.buffer.toString("base64");

    console.log("Image received. Sending to Gemini for analysis...");

    // Send to Gemini Flash 2.0 for evaluation
    const result = await model.generateContent({
      contents: [
        {
          role: "user",
          parts: [
            {
              text: `Analyze this website screenshot and determine if it's a fake or a cloned site.
              Provide the following structured data in JSON format:
              - give domain name of that website if it exists ,if not provide not found
              - legitimacy_score (0-100, with 100 being most legit)
              - red_flags (list of any suspicious elements)
              - verified_elements (list of elements that match a real site)
              - phishing_risk_level (Low, Medium, High)
              - suggested_actions (practical tips for the user)
              - full_analysis (detailed explanation of findings)`,
            },
            { inlineData: { mimeType: req.file.mimetype, data: base64Image } },
          ],
        },
      ],
    });

    const responseText = result.response.text();
    console.log("Gemini Response:", responseText);

    // Remove any Markdown code block formatting (json ... )
    const cleanedResponse = responseText.replace(/```json|```/g, "").trim();

    try {
      const analysis = JSON.parse(cleanedResponse);
      return res.json(analysis);
    } catch (error) {
      console.error("JSON Parsing Error:", error);
      return res.status(500).json({ error: "Failed to parse Gemini response" });
    }
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
