document.addEventListener('DOMContentLoaded', function() {
    // Add click event listeners to all remediation headers
    var headers = document.querySelectorAll('.remediation-header');
    headers.forEach(function(header) {
        header.addEventListener('click', function() {
            var checkId = header.getAttribute('data-check-id');
            var content = document.getElementById('remediation-' + checkId);
            var toggle = document.getElementById('toggle-' + checkId);
            
            if (content.style.display === 'none' || content.style.display === '') {
                content.style.display = 'block';
                toggle.textContent = '▼';
            } else {
                content.style.display = 'none';
                toggle.textContent = '▶';
            }
        });
    });
});