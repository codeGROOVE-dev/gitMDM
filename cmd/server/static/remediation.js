document.addEventListener("DOMContentLoaded", () => {
  // Add click event listeners to all remediation headers
  const headers = document.querySelectorAll(".remediation-header");
  headers.forEach((header) => {
    header.addEventListener("click", () => {
      const checkId = header.getAttribute("data-check-id");
      const content = document.getElementById(`remediation-${checkId}`);
      const toggle = document.getElementById(`toggle-${checkId}`);

      if (content.style.display === "none" || content.style.display === "") {
        content.style.display = "block";
        toggle.textContent = "▼";
      } else {
        content.style.display = "none";
        toggle.textContent = "▶";
      }
    });
  });
});
