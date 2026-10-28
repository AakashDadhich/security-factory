import child_process, { exec } from "child_process";
import express from "express";
const app = express();

app.get("/ping", (req, res) => {
  // ruleid: child-process-exec-request-data
  child_process.exec("ping -c 1 " + req.query.host, () => {});
  res.end();
});

app.get("/ping2", (req, res) => {
  const host = req.body.host;
  // ruleid: child-process-exec-request-data
  exec(`ping -c 1 ${host}`);
  res.end();
});

app.get("/fixed", (req, res) => {
  // ok: child-process-exec-request-data
  child_process.exec("uptime");
  res.end();
});

app.get("/numeric", (req, res) => {
  // ok: child-process-exec-request-data
  child_process.exec("sleep " + parseInt(req.query.n));
  res.end();
});
