import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { chromium } from "playwright";

const { origin, token, viewer, artifact, target, cancellable, screenshot } = JSON.parse(readFileSync(0, "utf8"));
const browser = await chromium.launch({ executablePath: process.env.PARSBACKUP_BROWSER });
let page;
try {
  // The ephemeral loopback fixture uses a locally generated certificate.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1160, height: 800 } });
  page = await context.newPage();
  page.setDefaultTimeout(20_000);
  const errors = [];
  const external = [];
  page.on("pageerror", error => errors.push(error.name));
  page.on("request", request => { if (new URL(request.url()).origin !== origin) external.push("Unexpected origin"); });

  const heading = (name) => page.getByRole("heading", { name, exact: true });
  const button = (name) => page.getByRole("button", { name, exact: true });
  const link = (name) => page.getByRole("link", { name, exact: true });
  const visible = (locator) => locator.waitFor({ state: "visible" });
  async function signIn(secret) {
    await visible(heading("Sign in"));
    await page.getByLabel("Operator token").fill(secret);
    await button("Sign in").click();
  }
  async function artifactDetails() {
    await link("Artifacts").click();
    await link(artifact).click();
    await visible(heading("Artifact details"));
  }

  await page.goto(origin);
  await signIn(token);
  await visible(heading("Overview"));
  await visible(page.getByText("Ready", { exact: true }));
  await visible(page.getByText("Available", { exact: true }));
  if (screenshot) await page.screenshot({ path: screenshot });
  const cookies = await context.cookies(origin);
  const sessionCookie = cookies.find(cookie => cookie.name === "__Host-backupctl");
  assert(sessionCookie?.httpOnly && sessionCookie.secure && sessionCookie.sameSite === "Strict");
  assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);

  await link("Jobs").click();
  await link(cancellable).click();
  await button("Request cancellation").click();
  await visible(page.getByText("Cancelled", { exact: true }));

  await artifactDetails();
  const interrupted = [];
  const url = "**/api/v1/inspections";
  const stop = async route => {
    interrupted.push([route.request().headers()["idempotency-key"], route.request().postData()]);
    await route.abort();
  };
  await page.route(url, stop, { times: 1 });
  await button("Inspect artifact").click();
  await visible(button("Retry same submission"));
  const retry = page.waitForRequest(request => request.url() === origin + "/api/v1/inspections");
  await button("Retry same submission").click();
  const request = await retry;
  assert(interrupted[0][0]);
  assert.deepEqual([request.headers()["idempotency-key"], request.postData()], interrupted[0]);
  await visible(heading("Inspection result"));
  await visible(page.getByText("Succeeded", { exact: true }));

  await artifactDetails();
  await button("Verify artifact").click();
  await visible(heading("Verification result"));
  await visible(page.getByText("Archive check", { exact: true }));
  await visible(page.getByText("Passed", { exact: true }));

  await artifactDetails();
  await link("Plan a restore").click();
  await page.getByLabel("Target database", { exact: true }).fill(target);
  await page.getByLabel("I confirm this is a synthetic fixture").check();
  await button("Create restore plan").click();
  await visible(heading("Review restore plan"));
  const planJobUrl = page.url();
  const confirmation = page.getByLabel("Type the exact target database");
  await confirmation.fill(target + "_wrong");
  assert(await button("Confirm restore").isDisabled());
  await confirmation.fill(target);
  if (screenshot) {
    await page.getByRole("region", { name: "Review restore plan" })
      .screenshot({ path: screenshot.replace(/\.png$/, "-restore.png") });
  }
  await button("Confirm restore").click();
  await visible(heading("Restore result"));
  await visible(page.getByText(target, { exact: true }));
  await page.reload();
  await visible(heading("Restore result"));

  await page.goto(planJobUrl);
  await visible(link("View restore job"));
  assert.equal(await button("Confirm restore").count(), 0);
  await link("Jobs").click();
  await visible(page.getByRole("table", { name: "Jobs in identifier order" }));
  await visible(page.getByRole("cell", { name: "Restore", exact: true }));
  await button("Sign out").click();
  await visible(heading("Sign in"));
  assert.equal((await context.cookies(origin)).length, 0);

  await signIn(viewer);
  await visible(heading("Jobs"));
  await artifactDetails();
  await visible(page.getByText("Job actions are unavailable for this artifact or session."));
  assert.equal(await button("Inspect artifact").count(), 0);
  await page.setViewportSize({ width: 370, height: 760 });
  await link("Overview").click();
  await visible(heading("Overview"));
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  console.log("Browser passed sign-in, cancellation, same-key retry, archive checks, exact restore confirmation, receipts, logout and viewer gating");
} catch (error) {
  if (page) console.error("Console alerts:", await page.getByRole("alert").allTextContents());
  throw error;
} finally {
  await browser.close();
}
