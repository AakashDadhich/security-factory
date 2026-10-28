import express from "express";
const app = express();

app.get("/a", (req, res) => {
  // ruleid: cookie-without-httponly-secure
  res.cookie("sid", "abc");
  // ruleid: cookie-without-httponly-secure
  res.cookie("sid", "abc", { httpOnly: true });
  // ruleid: cookie-without-httponly-secure
  res.cookie("sid", "abc", { secure: true, maxAge: 1000 });
  // ok: cookie-without-httponly-secure
  res.cookie("sid", "abc", { httpOnly: true, secure: true, sameSite: "strict" });
  // ok: cookie-without-httponly-secure
  res.cookie("sid", "abc", { secure: true, httpOnly: true });
  res.end();
});
