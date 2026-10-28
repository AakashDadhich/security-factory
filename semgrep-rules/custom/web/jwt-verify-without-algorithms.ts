import jwt from "jsonwebtoken";

// ruleid: jwt-verify-without-algorithms
const a = jwt.verify(token, secret);

// ruleid: jwt-verify-without-algorithms
const b = jwt.verify(token, secret, { issuer: "me" });

// ruleid: jwt-verify-without-algorithms
jwt.verify(token, secret, (err, decoded) => {});

// ok: jwt-verify-without-algorithms
const c = jwt.verify(token, secret, { algorithms: ["HS256"] });

// ok: jwt-verify-without-algorithms
const d = jwt.verify(token, secret, { issuer: "me", algorithms: ["RS256"] });
