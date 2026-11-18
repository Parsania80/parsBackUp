import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { chromium } from "playwright";

const { origin, token, viewer, backupToken, artifact, target, cancellable, screenshot, profileScreenshot } =
  JSON.parse(readFileSync(0, "utf8"));
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
  await link("Profiles").click();
  const daily = page.getByRole("row", { name: /Daily fixture/ });
  await visible(daily.getByRole("cell", { name: "None", exact: true }));
  await visible(page.getByText("Your session cannot start backups."));
  assert.equal(await button("Start backup").count(), 0);
  await artifactDetails();
  await visible(page.getByText("Job actions are unavailable for this artifact or session."));
  assert.equal(await button("Inspect artifact").count(), 0);
  await page.setViewportSize({ width: 370, height: 760 });
  await link("Overview").click();
  await visible(heading("Overview"));
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await button("Sign out").click();

  await signIn(backupToken);
  await link("Profiles").click();
  await visible(daily.getByText("Backup", { exact: true }));
  await visible(page.getByRole("row", { name: /Prune fixture/ }).getByRole("cell", { name: "None", exact: true }));
  const profile = page.getByLabel("Backup profile");
  const synthetic = page.getByLabel("I confirm this is a synthetic fixture");
  const startBackup = button("Start backup");
  await visible(startBackup);
  assert(await startBackup.isDisabled());
  assert.deepEqual(await profile.locator("option").evaluateAll(options => options.map(option => option.value)),
    ["", "daily", "default"]);
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await profile.selectOption("default");
  await synthetic.check();
  await profile.selectOption("daily");
  assert(!await synthetic.isChecked());
  assert(await startBackup.isDisabled());
  await synthetic.check();
  if (profileScreenshot) {
    await page.setViewportSize({ width: 1160, height: 800 });
    await page.screenshot({ path: profileScreenshot });
  }

  const backupUrl = origin + "/api/v1/backups";
  let accepted;
  await page.route(backupUrl, async route => {
    const response = await route.fetch();
    accepted = {
      status: response.status(), job: (await response.json()).data?.id,
      key: route.request().headers()["idempotency-key"], body: route.request().postDataJSON(),
    };
    await route.abort();
  }, { times: 1 });
  await startBackup.click();
  await visible(button("Retry same submission"));
  assert.equal(accepted?.status, 202);
  assert(accepted.job && accepted.key);
  assert.deepEqual(accepted.body, { profile_id: "daily", confirm_synthetic: true });
  assert(await profile.isDisabled());
  const replay = page.waitForRequest(request => request.url() === backupUrl);
  await button("Retry same submission").click();
  const replayRequest = await replay;
  assert.equal(replayRequest.headers()["idempotency-key"], accepted.key);
  assert.deepEqual(replayRequest.postDataJSON(), accepted.body);
  const result = page.getByRole("heading", { name: "Backup result", exact: true });
  await visible(result);
  assert.equal(new URL(page.url()).hash, "#/jobs/" + accepted.job);
  await page.locator("section").filter({ has: result }).getByRole("link").click();
  await button("Inspect artifact").click();
  await visible(heading("Inspection result"));
  await visible(page.getByText("sample-only", { exact: true }));

  await link("Profiles").click();
  await profile.selectOption("default");
  await synthetic.check();
  const defaultBackup = page.waitForRequest(request => request.url() === backupUrl);
  await startBackup.click();
  assert.deepEqual((await defaultBackup).postDataJSON(), { profile_id: null, confirm_synthetic: true });
  await visible(result);
  await visible(page.getByText("Succeeded", { exact: true }));
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  console.log("Browser passed sign-in, cancellation, same-key retry, archive checks, exact restore confirmation, receipts, logout and viewer gating");
  console.log("Browser passed named and default backups, profile filtering, scoped artifact inspection and replay after a lost receipt");
} catch (error) {
  if (page) console.error("Console alerts:", await page.getByRole("alert").allTextContents());
  throw error;
} finally {
  await browser.close();
}
