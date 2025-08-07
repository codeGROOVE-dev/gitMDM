function toggleCheck(header) {
    const checkItem = header.parentElement;
    checkItem.classList.toggle('expanded');
}

document.addEventListener('DOMContentLoaded', function() {
    // Add click listeners to check headers
    document.querySelectorAll('.check-header').forEach(header => {
        header.addEventListener('click', function() {
            toggleCheck(this);
        });
    });

    // Filter functionality
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Update active button
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            // Filter checks
            const filter = this.dataset.filter;
            document.querySelectorAll('.check-item').forEach(item => {
                if (filter === 'all' || item.dataset.status === filter) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });

    // Auto-expand failed checks
    document.querySelectorAll('.check-item[data-status="fail"]').forEach(item => {
        // Optionally auto-expand failed checks
        // item.classList.add('expanded');
    });
});