// nmap-triage web app: small enhancements on top of plain HTML forms.
// The page works without this file; it adds the tab switch, the file name,
// the "working..." overlay, and the download buttons.
(function () {
  "use strict";

  // --- Upload a scan / Run a scan -------------------------------------------
  var switches = Array.prototype.slice.call(document.querySelectorAll("[data-switch]"));

  function showPanel(name) {
    switches.forEach(function (btn) {
      var on = btn.getAttribute("data-switch") === name;
      btn.setAttribute("aria-pressed", on ? "true" : "false");
      var panel = document.getElementById(btn.getAttribute("aria-controls"));
      if (panel) panel.hidden = !on;
    });
  }

  switches.forEach(function (btn) {
    btn.addEventListener("click", function () {
      showPanel(btn.getAttribute("data-switch"));
    });
  });

  // --- File picker: show the chosen file, highlight while dragging ----------
  var fileInput = document.getElementById("scan-file");
  if (fileInput) {
    var drop = fileInput.closest(".drop");
    var fileName = drop.querySelector("[data-file-name]");

    fileInput.addEventListener("change", function () {
      var file = fileInput.files && fileInput.files[0];
      fileName.hidden = !file;
      fileName.textContent = file ? "Selected: " + file.name : "";
      drop.classList.toggle("drop--has-file", Boolean(file));
      clearFormError(fileInput.form);
    });

    ["dragenter", "dragover"].forEach(function (type) {
      drop.addEventListener(type, function () { drop.classList.add("drop--over"); });
    });
    ["dragleave", "drop"].forEach(function (type) {
      drop.addEventListener(type, function () { drop.classList.remove("drop--over"); });
    });
  }

  function showFormError(form, message) {
    var box = form.querySelector("[data-form-error]");
    if (!box) {
      box = document.createElement("div");
      box.className = "alert alert--error";
      box.setAttribute("role", "alert");
      box.setAttribute("data-form-error", "");
      form.insertBefore(box, form.querySelector(".actions"));
    }
    box.textContent = message;
  }

  function clearFormError(form) {
    var box = form && form.querySelector("[data-form-error]");
    if (box) box.remove();
  }

  // --- Working overlay with elapsed time ------------------------------------
  var overlay = document.querySelector("[data-busy-overlay]");
  var timer = null;

  function startBusy(title, hint) {
    if (!overlay) return;
    overlay.querySelector("[data-busy-title]").textContent = title;
    overlay.querySelector("[data-busy-hint]").textContent = hint;
    var timeEl = overlay.querySelector("[data-busy-time]");
    var started = Date.now();
    timeEl.textContent = "0:00";
    overlay.hidden = false;
    timer = setInterval(function () {
      var s = Math.floor((Date.now() - started) / 1000);
      timeEl.textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    }, 1000);
  }

  function stopBusy() {
    if (overlay) overlay.hidden = true;
    clearInterval(timer);
    document.querySelectorAll("form[data-busy] button").forEach(function (b) {
      b.disabled = b.hasAttribute("data-was-disabled");
    });
    document.querySelectorAll("input[data-submitter-copy]").forEach(function (el) { el.remove(); });
  }

  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.querySelectorAll("button[disabled]").forEach(function (b) {
      b.setAttribute("data-was-disabled", "");
    });

    form.addEventListener("submit", function (event) {
      var submitter = event.submitter;

      // "Analyze scan" needs a file. "Try the sample scan" doesn't.
      if (submitter && submitter.hasAttribute("data-needs-file") &&
          fileInput && !fileInput.files.length) {
        event.preventDefault();
        showFormError(form, "Choose an Nmap XML file first, or try the sample scan.");
        return;
      }

      // Disabled buttons aren't sent, so keep the clicked button's value.
      if (submitter && submitter.name) {
        var copy = document.createElement("input");
        copy.type = "hidden";
        copy.name = submitter.name;
        copy.value = submitter.value;
        copy.setAttribute("data-submitter-copy", "");
        form.appendChild(copy);
      }
      form.querySelectorAll("button").forEach(function (b) { b.disabled = true; });

      var aiBox = form.querySelector('input[name="ai"]');
      var usingAi = aiBox && aiBox.checked && !aiBox.disabled;
      var title, hint;
      if (form.id === "panel-scan") {
        title = "Scanning " + form.querySelector('input[name="target"]').value.trim();
        hint = "Scans can take a few minutes. Keep this tab open.";
      } else {
        title = submitter && submitter.name === "sample"
          ? "Analyzing the sample scan" : form.getAttribute("data-busy");
        hint = usingAi ? "AI triage can take up to a minute." : "";
      }
      startBusy(title, hint);
    });
  });

  // Coming back with the browser's Back button: clear the overlay.
  window.addEventListener("pageshow", stopBusy);

  // --- Results: jump to them, and the download buttons ----------------------
  var results = document.getElementById("results");
  if (results && !location.hash) {
    var smooth = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    results.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
  }

  var dataEl = document.getElementById("report-data");
  if (dataEl) {
    var report = JSON.parse(dataEl.textContent);
    var kinds = {
      md: ["text/markdown", ".md"],
      json: ["application/json", ".json"],
      txt: ["text/plain", ".txt"]
    };

    document.querySelectorAll("[data-download]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = kinds[btn.getAttribute("data-download")];
        var blob = new Blob([report[btn.getAttribute("data-download")]],
                            { type: kind[0] + ";charset=utf-8" });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = report.name + kind[1];
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      });
    });
  }
})();
