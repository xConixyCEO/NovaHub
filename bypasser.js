// bypasser.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const BYPASS_PORT = process.env.BYPASS_PORT || 10001;
const REQUEST_TIMEOUT = 10000; // ms

/* =============================================
   HEADERS & BASIC UTILITIES
============================================= */

// Mobile UA (primary)
const FAKE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) " +
  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

// Desktop UA (fallback / CF bypass)
const browserHeaders = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-Dest": "document",
  "Upgrade-Insecure-Requests": "1"
};

function randomString() {
  return Math.floor(Math.random() * 1e7).toString();
}

function isBase64(str) {
  if (!str || typeof str !== "string") return false;
  try {
    const decoded = Buffer.from(str, "base64").toString("utf8");
    return Buffer.from(decoded, "utf8").toString("base64") === str.replace(/=+$/, "");
  } catch {
    return false;
  }
}

/* =============================================
   REQUEST HELPERS
============================================= */

function uaGet(url) {
  return axios.get(url, {
    headers: {
      "User-Agent": FAKE_UA,
      "Accept": "application/json, text/plain, */*"
    },
    timeout: REQUEST_TIMEOUT
  });
}

function uaPost(url, data, extraHeaders = {}) {
  return axios.post(url, data, {
    headers: Object.assign(
      {
        "User-Agent": FAKE_UA,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*"
      },
      extraHeaders
    ),
    timeout: REQUEST_TIMEOUT
  });
}

// Desktop browser GET (for Cloudflare fallback)
function browserGet(url) {
  return axios.get(url, {
    headers: browserHeaders,
    timeout: REQUEST_TIMEOUT
  });
}

/* =============================================
   OPTIONAL CACHE
============================================= */

const cache = new Map();

function cacheSet(key, value, ttl = 600000) {
  cache.set(key, { value, exp: Date.now() + ttl });
}

function cacheGet(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.exp) {
    cache.delete(key);
    return null;
  }
  return entry.value;
}

/* =============================================
   LINKVERTISE INTERNAL BYPASS (FULL)
============================================= */

async function bypassLinkvertisePath(pathPart, linkvertiseUT = null) {
  const cacheKey = `lv:${pathPart}:${linkvertiseUT}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  // Warmup URLs
  const warmPaths = [
    "/captcha",
    "/countdown_impression?trafficOrigin=network",
    "/todo_impression?mobile=true&trafficOrigin=network"
  ];
  for (const p of warmPaths) {
    const warmUrl = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`;
    uaGet(warmUrl).catch(() => {});
  }

  // STEP 1 — get static metadata
  const staticUrl =
    `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;

  let staticResp;
  try {
    staticResp = await uaGet(staticUrl);
  } catch (err) {
    try {
      staticResp = await browserGet(staticUrl);
    } catch (err2) {
      throw {
        status: 502,
        message: "Failed Linkvertise static endpoint",
        details: axiosErrorDetails(err2)
      };
    }
  }

  if (!staticResp?.data?.data?.link) {
    throw { status: 502, message: "Invalid Linkvertise static response" };
  }

  const linkData = staticResp.data.data.link;

  let targetType = linkData.target_type;
  let link_target_type =
    targetType === "URL" ? "target" :
    targetType === "PASTE" ? "paste" :
    null;

  if (!link_target_type) {
    throw { status: 502, message: "Unsupported Linkvertise target type" };
  }

  // STEP 2 — create serial payload
  const serialObj = {
    timestamp: Date.now(),
    random: randomString(),
    link_id: linkData.id
  };
  const serial = Buffer.from(JSON.stringify(serialObj)).toString("base64");

  const postPayload = { serial };

  // STEP 3 — POST request
  const targetEndpoint =
    `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` +
    (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : "");

  let postResp;
  try {
    postResp = await uaPost(targetEndpoint, postPayload);
  } catch (err) {
    try {
      postResp = await axios.post(targetEndpoint, postPayload, {
        headers: Object.assign(
          { "Content-Type": "application/json" },
          browserHeaders
        ),
        timeout: REQUEST_TIMEOUT
      });
    } catch (err2) {
      throw {
        status: 502,
        message: "Linkvertise POST failed",
        details: axiosErrorDetails(err2)
      };
    }
  }

  if (!postResp?.data?.data) {
    throw { status: 502, message: "Invalid POST response" };
  }

  const result = {};

  if (link_target_type === "target") {
    result.decodedUrl = postResp.data.data.target;
  } else {
    result.paste = postResp.data.data.paste.trim();
  }

  cacheSet(cacheKey, result);
  return result;
}

function axiosErrorDetails(err) {
  if (!err) return null;
  if (err.response?.data) return err.response.data;
  if (err.message) return err.message;
  return String(err);
}

/* =============================================
   API ENDPOINT: /api/bypass
============================================= */

app.get("/api/bypass", async (req, res) => {
  try {
    // Base64 mode
    if (req.query.r) {
      const encoded = req.query.r;
      if (!isBase64(encoded))
        return res.status(400).json({
          success: false,
          error: "Invalid Base64 in ?r="
        });

      const decodedUrl = Buffer.from(encoded, "base64").toString("utf8");
      return res.json({ success: true, type: "base64", decodedUrl });
    }

    if (req.query.url) {
      const rawUrl = req.query.url;
      let parsed;

      try {
        parsed = new URL(rawUrl);
      } catch (err) {
        return res.status(400).json({
          success: false,
          error: "Invalid URL format",
          details: err.message
        });
      }

      // loot-link.com
      if (parsed.hostname === "loot-link.com" && parsed.searchParams.get("r")) {
        const encoded = parsed.searchParams.get("r");
        if (!isBase64(encoded))
          return res.status(400).json({
            success: false,
            error: "Invalid Base64 on loot-link"
          });

        const decodedUrl = Buffer.from(encoded, "base64").toString("utf8");
        return res.json({ success: true, service: "loot-link", decodedUrl });
      }

      // gateway.platoboost.com
      if (
        parsed.hostname === "gateway.platoboost.com" &&
        parsed.searchParams.get("id")
      ) {
        const encoded = parsed.searchParams.get("id");
        if (!isBase64(encoded))
          return res.status(400).json({
            success: false,
            error: "Invalid Base64 on platoboost"
          });

        const decodedUrl = Buffer.from(encoded, "base64").toString("utf8");
        return res.json({
          success: true,
          service: "platoboost",
          decodedUrl
        });
      }

      // generic ?r=
      if (parsed.searchParams.get("r")) {
        const encoded = parsed.searchParams.get("r");
        if (!isBase64(encoded))
          return res
            .status(400)
            .json({ success: false, error: "Invalid Base64 in ?r=" });

        const decodedUrl = Buffer.from(encoded, "base64").toString("utf8");
        return res.json({
          success: true,
          service: "generic-r",
          decodedUrl
        });
      }

      // generic ?id=
      if (parsed.searchParams.get("id")) {
        const encoded = parsed.searchParams.get("id");
        if (isBase64(encoded)) {
          const decodedUrl = Buffer.from(encoded, "base64").toString("utf8");
          return res.json({
            success: true,
            service: "generic-id",
            decodedUrl
          });
        }
      }

      // Linkvertise
      if (parsed.hostname.includes("linkvertise")) {
        const re = /^(\/[0-9]+\/[^\/]+)/;
        const match = re.exec(parsed.pathname);
        if (!match) {
          return res.status(400).json({
            success: false,
            error: "Invalid Linkvertise path format"
          });
        }

        const pathPart = match[1];
        const ut = req.query.ut || req.header("x-linkvertise-ut") || null;

        try {
          const result = await bypassLinkvertisePath(pathPart, ut);
          return res.json({
            success: true,
            service: "linkvertise",
            ...result
          });
        } catch (err) {
          return res.status(err.status || 502).json({
            success: false,
            error: err.message || "Linkvertise error",
            details: err.details || null
          });
        }
      }

      return res.status(400).json({
        success: false,
        error: "Unsupported URL. Provide Base64, Linkvertise, Platoboost, etc."
      });
    }

    return res.status(400).json({
      success: false,
      error: "Missing parameters. Use ?r=BASE64 or ?url=LINK"
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Internal server error",
      details: err.message || err
    });
  }
});

/* =============================================
   SERVER LISTENER
============================================= */
app.listen(BYPASS_PORT, () => {
  console.log(`Bypasser running on port ${BYPASS_PORT}`);
});
