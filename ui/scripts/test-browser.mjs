import assert from "node:assert/strict";
import { chromium, firefox } from "playwright";

export function launchTestBrowser() {
  const engine = process.env.PARSBACKUP_BROWSER_ENGINE ?? "chromium";
  assert(["chromium", "firefox"].includes(engine), "Choose chromium or firefox");
  return (engine === "firefox" ? firefox : chromium).launch({
    executablePath: process.env.PARSBACKUP_BROWSER,
  });
}
