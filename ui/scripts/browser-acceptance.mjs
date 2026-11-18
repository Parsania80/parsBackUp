import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import axe from "axe-core";
import { chromium } from "playwright";

const fixture = JSON.parse(readFileSync(0, "utf8"));
const browser = await chromium.launch({ executablePath: process.env.PARSBACKUP_BROWSER });
let page;
try {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1160, height: 800 } });
  page = await context.newPage();
  const api = fixture.origin + "/api/v1";
  page.setDefaultTimeout(15_000);
  const browserErrors = [];
  let restorePosts = 0;

  page.on("pageerror", error => browserErrors.push(error.name));
  page.on("request", request => {
    if (new URL(request.url()).origin !== fixture.origin) browserErrors.push("Unexpected origin");
    if (request.url() === api + "/restores" && request.method() === "POST") restorePosts++;
  });

  const heading = name => page.getByRole("heading", { name, exact: true });
  const link = name => page.getByRole("link", { name, exact: true });
  const button = name => page.getByRole("button", { name, exact: true });
  const text = name => page.getByText(name, { exact: true });
  const visible = locator => locator.waitFor({ state: "visible" });

  async function focusWithTab(locator) {
    await visible(locator);
    for (let n = 0; n < 45; n++) {
      if (await locator.evaluate(el => el === document.activeElement)) {
        assert(await locator.evaluate(el => {
          const style = getComputedStyle(el);
          return el.matches(":focus-visible") && style.outlineStyle !== "none" && parseFloat(style.outlineWidth) >= 3;
        }), "Keyboard focus must have a visible outline");
        return;
      }
      await page.keyboard.press("Tab");
    }
    assert.fail("Keyboard could not reach " + locator);
  }

  async function activate(locator, key = "Enter") {
    await focusWithTab(locator);
    await page.keyboard.press(key);
  }

  async function scan(name) {
    await page.evaluate(axe.source);
    const { violations, incomplete } = await page.evaluate(() => window.axe.run({
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] },
      rules: { "target-size": { enabled: true } },
    }));
    assert.deepEqual(violations.map(({ id, nodes }) => [id, nodes.map(node => node.target)]), [], name);
    const width = await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth]);
    assert(width[0] <= width[1], name + " reflows (" + width.join("/") + ")");
    const review = incomplete.map(rule => rule.id + " " + rule.nodes.map(node => node.target.join(" ")).join(", "));
    console.log("Accessibility " + name + ": zero automated violations" +
      (review.length ? "; manual rules: " + review.join(", ") : ""));
    if (fixture.screenshotDir) {
      await page.screenshot({ path: join(fixture.screenshotDir, name + ".png"), fullPage: true });
    }
  }

  async function signIn() {
    const response = page.waitForResponse(response => response.url() === api + "/session" &&
      response.request().method() === "POST" && response.status() === 201);
    await focusWithTab(page.getByLabel("Operator token"));
    await page.keyboard.insertText(fixture.token);
    await activate(button("Sign in"));
    return (await (await response).json()).data.expires_unix_ms;
  }

  async function showReceipt(id, state, caution, effects) {
    await activate(link(id));
    await visible(page.getByRole("status").getByText(state, { exact: true }));
    await visible(text(caution));
    await visible(text(effects));
    assert.equal(await button("Request cancellation").count(), 0);
    await scan(state.toLowerCase());
    await activate(link("Jobs"));
  }

  if (fixture.unavailable) {
    await page.goto(fixture.origin + "/#/profiles");
    await signIn();
    await visible(text("The API is currently refusing new jobs."));
    await page.getByLabel("Backup profile").selectOption("daily");
    await page.getByLabel("I confirm this is a synthetic fixture").check();
    assert(await button("Start backup").isDisabled());
    await scan("admission-unavailable");
    console.log("Live configuration change disabled backup admission.");
  } else {
    await page.clock.install();
    await context.addCookies([{ name: "__Host-backupctl", value: fixture.expired,
      url: fixture.origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
    const expired = page.waitForResponse(response => response.url() === api + "/session" && response.status() === 401);
    await page.goto(fixture.origin);
    await expired;
    await visible(heading("Sign in"));
    await scan("sign-in");
    const sessionExpiry = await signIn();
    await visible(text("Ready"));
    await scan("overview");
    await activate(link("Skip to content"));
    assert.equal(await page.evaluate(() => document.activeElement.id), "main");

    await activate(link("Profiles"));
    const profileName = text(fixture.literal);
    await visible(profileName);
    assert.equal(await profileName.locator("em").count(), 0);
    assert.equal(await profileName.textContent(), fixture.literal);
    await page.setViewportSize({ width: 320, height: 720 });
    await scan("profiles-320");
    await focusWithTab(page.getByLabel("Backup profile"));
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Tab");
    assert.equal(await page.getByLabel("Backup profile").inputValue(), "default");
    const synthetic = page.getByLabel("I confirm this is a synthetic fixture");
    await activate(synthetic, "Space");
    assert(await synthetic.isChecked());
    await activate(button("Start backup"));
    const backupResult = heading("Backup result");
    await visible(backupResult);
    const freshArtifact = await page.locator("section").filter({ has: backupResult }).getByRole("link").textContent();
    assert(freshArtifact && freshArtifact !== fixture.artifact);
    await scan("backup-result-320");
    await page.setViewportSize({ width: 1160, height: 800 });

    await activate(link("Jobs"));
    await visible(link(fixture.partial));
    await scan("jobs");
    await showReceipt(fixture.partial, "Partial",
      "Work ended with possible effects. Inspect them before starting a new attempt.",
      "Database state may have changed");
    await showReceipt(fixture.interrupted, "Interrupted",
      "Work was interrupted. Inspect the job and any target before starting a new attempt.",
      "Effects unknown");

    await page.route(api + "/artifacts", route => route.abort(), { times: 1 });
    await activate(link("Artifacts"));
    await visible(page.getByRole("alert").getByText("The connection to the API was lost."));
    await scan("artifact-read-error");
    await activate(button("Refresh"));
    await visible(link(fixture.artifact));
    await page.setViewportSize({ width: 320, height: 720 });
    await scan("artifacts-320");
    await activate(link(freshArtifact));
    await visible(heading("Artifact details"));
    await activate(link("Plan a restore"));
    const target = page.getByLabel("Target database", { exact: true });
    await focusWithTab(target);
    await page.keyboard.insertText("invalid");
    await activate(synthetic, "Space");
    await activate(button("Create restore plan"));
    await visible(text("Enter a fixture database name using lowercase letters, numbers or underscores."));
    await page.waitForFunction(() => document.activeElement.id === "target");
    assert.equal(await target.getAttribute("aria-invalid"), "true");
    assert.equal(await target.getAttribute("aria-describedby"), "target-help");
    await scan("restore-invalid-320");
    await focusWithTab(target);
    await page.keyboard.press("Control+a");
    await page.keyboard.insertText(fixture.target);
    await activate(button("Create restore plan"));
    await visible(heading("Review restore plan"));
    const confirmation = page.getByLabel("Type the exact target database");
    await focusWithTab(confirmation);
    await page.keyboard.insertText(fixture.target + "_wrong");
    await page.keyboard.press("Enter");
    assert(await button("Confirm restore").isDisabled());
    assert.equal(restorePosts, 0);
    await scan("restore-review-320");
    await focusWithTab(confirmation);
    await page.keyboard.press("Control+a");
    await page.keyboard.insertText(fixture.target);
    await activate(button("Confirm restore"));
    await visible(heading("Restore result"));
    await visible(text(fixture.target));
    assert.equal(restorePosts, 1);
    await scan("restore-result-320");

    const remaining = sessionExpiry - await page.evaluate(() => Date.now());
    assert(remaining > 0);
    await page.clock.fastForward(remaining + 1000);
    await visible(heading("Sign in"));
    assert.equal(await heading("Restore result").count(), 0);
    console.log("Keyboard restore, network recovery, literal rendering, and server/client session expiry passed.");
  }
  assert.deepEqual(browserErrors, []);
} catch (error) {
  if (page) console.error("Console alerts:", await page.getByRole("alert").allTextContents().catch(() => []));
  throw error;
} finally {
  await browser.close();
}
