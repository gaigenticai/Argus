import { test, expect } from "@playwright/test";

// ─── Dashboard ───────────────────────────────────────────────
test.describe("Dashboard", () => {
  test("loads stats, charts, recent alerts, and crawler status", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Loading dashboard...")).toBeHidden({ timeout: 10000 });

    // Stat cards
    await expect(page.getByText("Total Alerts")).toBeVisible();
    await expect(page.getByText("New / Unreviewed")).toBeVisible();
    await expect(page.getByText("Resolved", { exact: true })).toBeVisible();

    // Charts
    await expect(page.getByText("Alerts by severity")).toBeVisible();
    await expect(page.getByText("Alerts by category")).toBeVisible();

    // Recent alerts table with actual data
    await expect(page.getByText("Recent alerts")).toBeVisible();
    const alertLinks = page.locator("table a, [href*='/alerts/']");
    await expect(alertLinks.first()).toBeVisible({ timeout: 5000 });

    // Crawler status
    await expect(page.getByText("Crawler status")).toBeVisible();
  });
});

// ─── Alerts ──────────────────────────────────────────────────
test.describe("Alerts", () => {
  test("list page loads alerts from API with filters", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await expect(page.getByText(/\d+ alerts found/)).toBeVisible();

    // Table headers
    await expect(page.getByRole("columnheader", { name: "Severity" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Title" })).toBeVisible();

    // Should have rows
    const rows = page.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);

    // Test severity filter
    await page.locator("select").first().selectOption("critical");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });
    const severityBadges = page.locator("tbody tr td:first-child span");
    const firstBadge = await severityBadges.first().textContent();
    expect(firstBadge?.toLowerCase()).toContain("critical");
  });

  test("alert detail page shows full analysis", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Click first alert link
    const firstLink = page.locator("tbody a").first();
    await firstLink.click();

    // Wait for navigation
    await page.waitForURL(/\/alerts\/.+/);

    // Wait for detail to load
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Alert title (in main content, not the sidebar ARGUS h1)
    await expect(page.locator("main h1")).toBeVisible();

    // Confidence bar
    await expect(page.getByText("Confidence:")).toBeVisible();

    // Status buttons
    await expect(page.getByRole("heading", { name: "Actions", exact: true })).toBeVisible();

    // Analyst notes
    await expect(page.getByPlaceholder("Add your investigation notes...")).toBeVisible();
    await expect(page.getByRole("button", { name: "Save notes" })).toBeVisible();
  });

  test("status update works on alert detail", async ({ page }) => {
    await page.goto("/alerts");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Find a "new" status alert
    const newRow = page.locator("tbody tr").filter({ hasText: /new/i }).first();
    await newRow.locator("a").click();
    await page.waitForURL(/\/alerts\/.+/);
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Click "triaged" button
    const triagedBtn = page.locator("button").filter({ hasText: "triaged" });
    await triagedBtn.click();
    await page.waitForTimeout(1500);

    // Should be active now
    await expect(triagedBtn).toHaveClass(/bg-\[#00A76F\]/);
  });
});

// ─── Organizations ───────────────────────────────────────────
test.describe("Organizations", () => {
  test("shows seeded organizations with details", async ({ page }) => {
    await page.goto("/organizations");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Seeded orgs
    await expect(page.getByRole("heading", { name: "Meridian Financial Group" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "NovaMed Health Systems" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Helios Semiconductor" })).toBeVisible();

    // Domain chips
    await expect(page.getByText("meridianfg.com")).toBeVisible();

    // Industry
    await expect(page.getByText("Financial Services").first()).toBeVisible();
    await expect(page.getByText("Healthcare").first()).toBeVisible();
  });

  test("create organization modal works", async ({ page }) => {
    await page.goto("/organizations");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await page.getByRole("button", { name: "Add organization" }).click();

    // Modal
    await expect(page.getByRole("heading", { name: "New organization" })).toBeVisible();

    // Fill form
    await page.getByPlaceholder("Acme Corporation").fill("Playwright Test Corp");
    await page.getByPlaceholder("acme.com, acme.io").fill("playwrighttest.com");
    await page.getByPlaceholder("Acme Corp, AcmeTech").fill("PlaywrightTest");
    await page.getByPlaceholder("Financial Services").fill("Technology");

    // Submit
    await page.locator(".fixed button").filter({ hasText: "Create" }).click();

    // Modal should close and org should appear
    await expect(page.getByRole("heading", { name: "New organization" })).toBeHidden({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: "Playwright Test Corp" }).first()).toBeVisible({ timeout: 5000 });
  });
});

// ─── Crawlers ────────────────────────────────────────────────
test.describe("Crawlers", () => {
  test("shows crawler list with run buttons", async ({ page }) => {
    await page.goto("/crawlers");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await expect(page.getByRole("heading", { name: "TorForumCrawler" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "TelegramCrawler" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "I2PEepsiteCrawler" })).toBeVisible();

    const runButtons = page.getByRole("button", { name: "Run now" });
    const count = await runButtons.count();
    expect(count).toBeGreaterThanOrEqual(5);

    await expect(page.getByRole("button", { name: "Run all" })).toBeVisible();
  });

  test("trigger crawler shows feedback", async ({ page }) => {
    await page.goto("/crawlers");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await page.getByRole("button", { name: "Run now" }).first().click();
    await expect(page.getByText("Running...").first()).toBeVisible();
  });
});

// ─── Attack Surface ──────────────────────────────────────────
test.describe("Attack Surface", () => {
  test("shows org selector and scan buttons", async ({ page }) => {
    await page.goto("/surface");
    await page.waitForTimeout(1000);

    const select = page.locator("select");
    await expect(select).toBeVisible();
    const optCount = await select.locator("option").count();
    expect(optCount).toBeGreaterThan(0);

    await expect(page.getByRole("button", { name: /Discover subdomains/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Check exposures/ })).toBeVisible();
  });

  test("check exposures triggers scan and shows toast", async ({ page }) => {
    await page.goto("/surface");
    await page.waitForTimeout(1000);

    await page.getByRole("button", { name: /Check exposures/ }).click();

    // Should see toast
    await expect(page.getByText(/scan started|Exposure scan/i)).toBeVisible({ timeout: 5000 });
  });
});

// ─── Reports ─────────────────────────────────────────────────
test.describe("Reports", () => {
  test("shows page and generate button", async ({ page }) => {
    await page.goto("/reports");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await expect(page.getByRole("heading", { name: "Reports", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Generate report" })).toBeVisible();
  });

  test("generate report modal has form fields", async ({ page }) => {
    await page.goto("/reports");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    await page.getByRole("button", { name: "Generate report" }).click();

    // Modal heading
    await expect(page.getByRole("heading", { name: "Generate report" })).toBeVisible();

    // Org select in modal
    const modalSelect = page.locator(".fixed select");
    await expect(modalSelect).toBeVisible();
    const options = await modalSelect.locator("option").count();
    expect(options).toBeGreaterThan(0);

    // Date inputs
    const dateInputs = page.locator('.fixed input[type="date"]');
    await expect(dateInputs.first()).toBeVisible();
    const dateCount = await dateInputs.count();
    expect(dateCount).toBe(2);

    // Generate PDF button
    await expect(page.getByRole("button", { name: "Generate PDF" })).toBeVisible();
  });
});

// ─── Notifications ───────────────────────────────────────────
test.describe("Notifications", () => {
  test("shows channel status cards and config", async ({ page }) => {
    await page.goto("/notifications");
    await expect(page.locator(".animate-spin")).toBeHidden({ timeout: 10000 });

    // Channel headings
    await expect(page.getByRole("heading", { name: "Slack" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Email" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "PagerDuty" })).toBeVisible();

    // Configuration section
    await expect(page.getByRole("heading", { name: "Configuration" })).toBeVisible();

    // Send test button
    await expect(page.getByRole("button", { name: "Send test" })).toBeVisible();
  });
});

// ─── Header Search ───────────────────────────────────────────
test.describe("Header Search", () => {
  test("search finds alerts by keyword", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Loading dashboard...")).toBeHidden({ timeout: 10000 });

    const searchInput = page.getByPlaceholder("Search alerts, organizations...");
    await searchInput.fill("LockBit");

    // Wait for search dropdown
    await expect(page.locator("text=Alerts").first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/LockBit/i).first()).toBeVisible();
  });

  test("search finds organizations by name", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Loading dashboard...")).toBeHidden({ timeout: 10000 });

    const searchInput = page.getByPlaceholder("Search alerts, organizations...");
    await searchInput.fill("Meridian");

    await page.waitForTimeout(500);
    await expect(page.locator("text=Organizations").first()).toBeVisible({ timeout: 5000 });
  });

  test("notification bell shows count and navigates", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Loading dashboard...")).toBeHidden({ timeout: 10000 });

    const bell = page.locator("header button").filter({ has: page.locator("svg.lucide-bell") });
    await expect(bell).toBeVisible();
    await bell.click();
    await expect(page).toHaveURL(/\/alerts/);
  });
});

// ─── Toast Positioning ───────────────────────────────────────
test.describe("Toast Notifications", () => {
  test("toast appears within main content area, not behind sidebar", async ({ page }) => {
    await page.goto("/surface");
    await page.waitForTimeout(1000);

    await page.getByRole("button", { name: /Check exposures/ }).click();

    const toast = page.locator("[class*='pointer-events-auto']").first();
    await expect(toast).toBeVisible({ timeout: 5000 });

    const box = await toast.boundingBox();
    expect(box).not.toBeNull();
    if (box) {
      expect(box.x).toBeGreaterThan(250);
      expect(box.x + box.width).toBeLessThanOrEqual(1440);
    }
  });
});

// ─── Activity Feed ───────────────────────────────────────────
test.describe("Activity Feed", () => {
  test("shows live activity page with SSE connection", async ({ page }) => {
    // Trigger a crawler first to generate at least one event
    await fetch("http://localhost:8000/api/v1/crawlers/tor_forum_crawler/run", { method: "POST" });
    await page.waitForTimeout(1000);

    await page.goto("/activity");
    await page.waitForTimeout(2000);

    // Page heading
    await expect(page.getByRole("heading", { name: "Live activity" })).toBeVisible();

    // Connection indicator
    await expect(page.getByText("Connected")).toBeVisible({ timeout: 5000 });

    // Toolbar elements
    await expect(page.getByPlaceholder("Filter events...")).toBeVisible();
    await expect(page.getByRole("button", { name: "Pause" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Clear" })).toBeVisible();
  });

  test("pause and clear buttons work", async ({ page }) => {
    await page.goto("/activity");
    await page.waitForTimeout(2000);

    // Click Pause
    await page.getByRole("button", { name: "Pause" }).click();
    await expect(page.getByText(/Resume/)).toBeVisible();

    // Click Clear
    await page.getByRole("button", { name: "Clear" }).click();
    await page.waitForTimeout(500);
  });
});

// ─── Navigation ──────────────────────────────────────────────
test.describe("Navigation", () => {
  test("sidebar links navigate to correct pages", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("Loading dashboard...")).toBeHidden({ timeout: 10000 });

    const links = [
      { text: "Alerts", url: "/alerts" },
      { text: "Organizations", url: "/organizations" },
      { text: "Attack Surface", url: "/surface" },
      { text: "Crawlers", url: "/crawlers" },
      { text: "Activity", url: "/activity" },
      { text: "Reports", url: "/reports" },
      { text: "Notifications", url: "/notifications" },
      { text: "Dashboard", url: "/" },
    ];

    for (const link of links) {
      await page.locator(`nav a:text("${link.text}")`).click();
      await expect(page).toHaveURL(link.url);
      await page.waitForTimeout(500);
    }
  });
});
