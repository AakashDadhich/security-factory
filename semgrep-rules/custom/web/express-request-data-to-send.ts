import express from "express";
const app = express();

app.get("/echo", (req, res) => {
  // ruleid: express-request-data-to-send
  res.send(req.query.name);
});

app.post("/echo", (req, res) => {
  const name = req.body.name;
  // ruleid: express-request-data-to-send
  res.send("<p>" + name + "</p>");
});

app.get("/safe", (req, res) => {
  // ok: express-request-data-to-send
  res.send(escapeHtml(req.query.name));
});

app.get("/count", (req, res) => {
  // ok: express-request-data-to-send
  res.send(String(parseInt(req.query.n)));
});

app.get("/static", (req, res) => {
  // ok: express-request-data-to-send
  res.send("hello");
});
