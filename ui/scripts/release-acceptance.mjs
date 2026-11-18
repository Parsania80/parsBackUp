import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { launchTestBrowser } from "./test-browser.mjs";

const fixture = JSON.parse(readFileSync(0, "utf8"));
const browser = await launchTestBrowser();
try {
  const page = await browser.newPage({ ignoreHTTPSErrors: true });
  page.setDefaultTimeout(15_000);
  let restores = 0;
  page.on("request", request => {
    if (request.method() === "POST" && request.url() === fixture.origin + "/api/v1/restores") restores++;
  });
  const click = (role, name) => page.getByRole(role, { name, exact: true }).click();
  await page.goto(fixture.origin);
  await page.getByLabel("Operator token").fill(fixture.token);
  await click("button", "Sign in");
  await click("link", "Artifacts");
  await click("link", fixture.artifact);
  await click("link", "Plan a restore");
  await page.getByLabel("Target database", { exact: true }).fill(fixture.target);
  await page.getByLabel("I confirm this is a synthetic fixture").check();
  await click("button", "Create restore plan");
  const confirmation = page.getByLabel("Type the exact target database");
  const confirm = page.getByRole("button", { name: "Confirm restore", exact: true });
  await confirmation.fill(fixture.target + "_wrong");
  assert(await confirm.isDisabled());
  assert.equal(restores, 0);
  await confirmation.fill(fixture.target);
  await confirm.click();
  await page.getByRole("heading", { name: "Restore result", exact: true }).waitFor();
  await page.getByText(fixture.target, { exact: true }).waitFor();
  assert.equal(restores, 1);
  console.log(`${browser.browserType().name()} ${browser.version()}: confirmed restoration of the selected archive`);
} finally {
  await browser.close();
}
