const express = require("express");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.static(path.join(__dirname, "public")));


/* =========================
   ALLOWED WEBSITES
========================= */

const allowedHosts = new Set([
    "example.com",
    "www.example.com"
]);


/* =========================
   SECURITY
========================= */

function isPrivateIPv4(ip) {

    const parts = ip.split(".").map(Number);

    if (
        parts.length !== 4 ||
        parts.some(Number.isNaN)
    ) {
        return false;
    }

    const [a, b] = parts;

    return (
        a === 10 ||
        a === 127 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a === 0
    );
}


async function hostnameIsSafe(hostname) {

    const normalized =
        hostname.toLowerCase();

    if (
        normalized === "localhost" ||
        normalized.endsWith(".localhost") ||
        normalized.endsWith(".local")
    ) {
        return false;
    }

    if (net.isIP(normalized) === 4) {
        return !isPrivateIPv4(normalized);
    }

    if (net.isIP(normalized) === 6) {
        return false;
    }

    try {

        const addresses =
            await dns.lookup(normalized, {
                all: true
            });

        return addresses.every(address => {

            if (address.family === 4) {
                return !isPrivateIPv4(
                    address.address
                );
            }

            return false;
        });

    } catch {

        return false;
    }
}


/* =========================
   PROXY
========================= */

app.get("/proxy", async (req, res) => {

    const target = req.query.url;

    if (!target) {
        return res
            .status(400)
            .send("Missing URL.");
    }


    let parsed;

    try {

        parsed = new URL(target);

    } catch {

        return res
            .status(400)
            .send("Invalid URL.");

    }


    if (
        !["http:", "https:"]
            .includes(parsed.protocol)
    ) {

        return res
            .status(400)
            .send(
                "Only HTTP and HTTPS are supported."
            );

    }


    /* Only allow sites on our list */

    if (
        !allowedHosts.has(
            parsed.hostname.toLowerCase()
        )
    ) {

        return res
            .status(403)
            .send(
                "This website isn't enabled in ZN yet."
            );

    }


    const safe =
        await hostnameIsSafe(
            parsed.hostname
        );

    if (!safe) {

        return res
            .status(403)
            .send(
                "That destination isn't allowed."
            );

    }


    try {

        const response =
            await fetch(parsed.href, {
                redirect: "manual",
                headers: {
                    "User-Agent":
                        "zyro.nerd/1.0"
                }
            });


        /*
          Don't blindly follow redirects.
          Only return the response we received.
        */

        const contentType =
            response.headers.get(
                "content-type"
            ) || "text/plain";


        const body =
            await response.text();


        res.status(
            response.status
        );


        res.set(
            "Content-Type",
            contentType
        );


        /*
          Remove headers that could prevent
          our own viewer from displaying HTML.
        */

        res.removeHeader(
            "X-Frame-Options"
        );

        res.removeHeader(
            "Content-Security-Policy"
        );


        res.send(body);


    } catch (error) {

        console.error(error);

        res.status(500).send(
            "ZN couldn't load this website."
        );

    }

});


/* =========================
   SERVER
========================= */

app.listen(PORT, () => {

    console.log(
        `zyro.nerd running at http://localhost:${PORT}`
    );

});