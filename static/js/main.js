/**
 * Main JavaScript for Phishing Detection System Frontend
 */

// Initialize all tooltips
const initTooltips = () => {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
};

// Initialize dashboard features
const initDashboard = () => {
    // Add animation to stat cards
    const statCards = document.querySelectorAll('.stat-card');
    if (statCards.length > 0) {
        statCards.forEach((card, index) => {
            setTimeout(() => {
                card.classList.add('animate__animated', 'animate__fadeInUp');
            }, index * 100);
        });
    }
    
    // Add hover effects to indicator items
    const indicatorItems = document.querySelectorAll('.indicator-item');
    if (indicatorItems.length > 0) {
        indicatorItems.forEach(item => {
            item.addEventListener('mouseenter', () => {
                item.classList.add('bg-light');
            });
            item.addEventListener('mouseleave', () => {
                item.classList.remove('bg-light');
            });
        });
    }
};

// Handle file upload visualization
const setupFileUpload = () => {
    const fileInput = document.getElementById('file-input');
    const dropArea = document.getElementById('drop-area');
    const fileName = document.getElementById('file-name');
    
    if (!fileInput || !dropArea || !fileName) return;
    
    // Display selected file name
    fileInput.addEventListener('change', function(e) {
        const selectedFile = e.target.files[0] ? e.target.files[0].name : '';
        fileName.textContent = selectedFile ? `Selected file: ${selectedFile}` : '';
        
        if (selectedFile) {
            dropArea.classList.add('border-primary');
            dropArea.classList.add('bg-light');
        } else {
            dropArea.classList.remove('border-primary');
            dropArea.classList.remove('bg-light');
        }
    });
    
    // Drag and drop functionality
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight() {
        dropArea.classList.add('border-primary');
        dropArea.classList.add('bg-light');
    }

    function unhighlight() {
        if (!fileInput.files.length) {
            dropArea.classList.remove('border-primary');
            dropArea.classList.remove('bg-light');
        }
    }

    dropArea.addEventListener('drop', handleDrop, false);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        fileInput.files = files;
        
        const selectedFile = files[0] ? files[0].name : '';
        fileName.textContent = selectedFile ? `Selected file: ${selectedFile}` : '';
    }
};

// Setup gauge visualization on result page
const setupGauge = () => {
    const gaugeFill = document.getElementById('gauge-fill');
    const confidenceValue = document.getElementById('confidence-value');
    
    if (!gaugeFill || !confidenceValue) return;
    
    const probability = parseFloat(confidenceValue.textContent);
    const angle = probability * 1.8; // 180 degrees is the full range (0-100%)
    
    gaugeFill.style.transform = `rotate(${angle}deg)`;
    
    // Add color based on probability
    if (probability >= 70) {
        confidenceValue.classList.add('text-danger');
    } else if (probability >= 30) {
        confidenceValue.classList.add('text-warning');
    } else {
        confidenceValue.classList.add('text-success');
    }
};

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    setupFileUpload();
    setupGauge();
    initDashboard();
    
    // Initialize any interactive elements on the result page
    const resultPage = document.querySelector('.result-header');
    if (resultPage) {
        // Add animation to evidence items when they become visible
        const evidenceItems = document.querySelectorAll('.evidence-item');
        if (evidenceItems.length > 0) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('bg-light');
                        observer.unobserve(entry.target);
                    }
                });
            });
            
            evidenceItems.forEach(item => {
                observer.observe(item);
            });
        }
    }
    
    // Add smooth scrolling for all links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});