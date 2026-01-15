// Search functionality
const searchInput = document.getElementById("searchInput");
let searchTimeout;

searchInput?.addEventListener("input", function () {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    const searchValue = this.value.trim();
    const urlParams = new URLSearchParams(window.location.search);

    if (searchValue) {
      urlParams.set("search", searchValue);
    } else {
      urlParams.delete("search");
    }

    urlParams.delete("page"); // Reset to page 1
    window.location.search = urlParams.toString();
  }, 500); // Debounce search
});

// Filter tabs
document.querySelectorAll(".filter-tab").forEach((tab) => {
  tab.addEventListener("click", function () {
    const status = this.dataset.status;
    const urlParams = new URLSearchParams(window.location.search);

    if (status) {
      urlParams.set("status", status);
    } else {
      urlParams.delete("status");
    }

    urlParams.delete("page"); // Reset to page 1
    window.location.search = urlParams.toString();
  });
});

// Clear search on Escape key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && searchInput) {
    searchInput.value = "";
    const urlParams = new URLSearchParams(window.location.search);
    urlParams.delete("search");
    urlParams.delete("page");
    window.location.search = urlParams.toString();
  }
});
