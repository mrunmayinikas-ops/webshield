document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scan-form");
  const targetInput = document.getElementById("target-url");
  const clearButton = document.getElementById("clear-button");
  const statusIndicator = document.getElementById("status-indicator");
  const scanMessage = document.getElementById("scan-message");
  const scanMetrics = document.getElementById("scan-metrics");
  const scanProgress = document.getElementById("scan-progress");
  const historyTableBody = document.getElementById("history-table-body");

  const setStatus = (state, message) => {
    if (!statusIndicator) return;
    statusIndicator.className = `status-indicator ${state}`;
    statusIndicator.textContent = message;
  };

  const setProgress = (value) => {
    if (!scanProgress) return;
    scanProgress.style.width = `${Math.max(0, Math.min(100, value))}%`;
  };

  const renderHistory = async () => {
    if (!historyTableBody) return;
    try {
      const response = await fetch("/api/history");
      const rows = await response.json();
      if (!rows.length) {
        historyTableBody.innerHTML =
          '<tr><td colspan="7">No saved scans yet.</td></tr>';
        return;
      }

      historyTableBody.innerHTML = rows
        .map(
          (row) => `
            <tr>
              <td>${row.id}</td>
              <td>${row.target_url}</td>
              <td>${row.scanned_at}</td>
              <td>${row.total_urls}</td>
              <td>${row.vulnerability_count}</td>
              <td>
                <span class="severity-badge critical">C:${row.critical}</span>
                <span class="severity-badge high">H:${row.high}</span>
                <span class="severity-badge medium">M:${row.medium}</span>
                <span class="severity-badge low">L:${row.low}</span>
                <span class="severity-badge informational">I:${row.informational}</span>
              </td>
              <td><a class="primary-button" href="/results/${row.id}">Open</a></td>
            </tr>
          `,
        )
        .join("");
    } catch (error) {
      historyTableBody.innerHTML =
        '<tr><td colspan="7">Unable to load scan history.</td></tr>';
    }
  };

  const pollScanStatus = async (jobId, targetUrl) => {
    const poll = async () => {
      const response = await fetch(`/api/scan/status/${jobId}`);
      if (!response.ok) {
        setStatus("error", "Scan Error");
        if (scanMessage)
          scanMessage.textContent = "The status endpoint could not be reached.";
        return;
      }

      const status = await response.json();
      if (scanMessage)
        scanMessage.textContent =
          status.message || "🐾 Cat is watching closely...";
      if (scanMetrics) {
        const limitText = status.crawl_limit_reached ? " | Crawl limit reached" : "";
        scanMetrics.textContent = `Pages discovered: ${status.pages_discovered || 0} | Pages scanned: ${status.pages_crawled || 0} | Remaining: ${status.pages_remaining || 0} | APIs discovered: ${status.apis_discovered || 0}${limitText}`;
      }
      setProgress(status.progress || 0);

      if (status.status === "running") {
        setStatus("running", "Scanning");
        setTimeout(poll, 500);
        return;
      }

      if (status.status === "completed") {
        setStatus("success", "Scan Complete");
        setProgress(100);
        if (scanMessage)
          scanMessage.textContent =
            "🐾 Scan complete. Redirecting to results...";
        window.location.href = `/results/${status.scan_id}`;
        return;
      }

      if (status.status === "error") {
        setStatus("error", "Scan Failed");
        if (scanMessage)
          scanMessage.textContent =
            status.error || "The scan could not be completed.";
      }
    };

    await poll();
  };

  if (scanForm) {
    scanForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const targetUrl = (targetInput.value || "").trim();

      if (!targetUrl) {
        setStatus("error", "Validation Error");
        if (scanMessage) scanMessage.textContent = "Please enter a target URL.";
        return;
      }

      setStatus("running", "Scanning");
      setProgress(8);
      if (scanMetrics)
        scanMetrics.textContent = "Pages discovered: 0 | Pages scanned: 0 | APIs discovered: 0";
      if (scanMessage)
        scanMessage.textContent = "🐾 Cat is sniffing the target...";

      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_url: targetUrl }),
        });

        const body = await response.json();
        if (!response.ok || body.error) {
          setStatus("error", "Scan Failed");
          if (scanMessage)
            scanMessage.textContent = body.error || "The scan failed.";
          return;
        }

        if (body.job_id) {
          pollScanStatus(body.job_id, targetUrl);
        } else {
          setStatus("success", "Scan Complete");
          if (scanMessage) scanMessage.textContent = "🐾 Scan complete.";
          if (body.scan_id) window.location.href = `/results/${body.scan_id}`;
        }
      } catch (error) {
        setProgress(0);
        setStatus("error", "Scan Error");
        if (scanMessage)
          scanMessage.textContent =
            "The scan could not be completed because the server is unavailable.";
      }
    });
  }

  if (clearButton && targetInput) {
    clearButton.addEventListener("click", () => {
      targetInput.value = "";
      setProgress(0);
      if (scanMessage) scanMessage.textContent = "🐾 Cat is waking up...";
      setStatus("idle", "Ready");
    });
  }

  renderHistory();
});
