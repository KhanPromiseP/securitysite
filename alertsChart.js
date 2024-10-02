// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function () {
    // Ensure this block only runs once
    var ctx = document.getElementById('alertsChart').getContext('2d');

    // Initialize the chart object
    var alertsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [], // Time labels (e.g., current time)
            datasets: [
                {
                    label: 'Suspicious Behavior',
                    data: [], // Data for this alert type
                    borderColor: 'rgba(255, 99, 132, 1)', // Muted but distinct color
                    backgroundColor: 'rgba(255, 99, 132, 0.2)', // Light fill color for area under the curve
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4, // Points on the line graph
                    pointHoverRadius: 6, // Larger points on hover
                    fill: true, // Filling under the curve
                    tension: 0.4 // Smooth curves
                },
                {
                    label: 'Suspicious Files',
                    data: [],
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Detected Vulnerabilities',
                    data: [],
                    borderColor: 'rgba(255, 206, 86, 1)',
                    backgroundColor: 'rgba(255, 206, 86, 0.2)',
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Suspicious Traffic',
                    data: [],
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Suspicious Emails',
                    data: [],
                    borderColor: 'rgba(153, 102, 255, 1)',
                    backgroundColor: 'rgba(153, 102, 255, 0.2)',
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Timestamp',
                        font: {
                            size: 16
                        }
                    },
                    type: 'category',
                    grid: {
                        color: '#ccc', // Light grid lines
                    },
                    ticks: {
                        color: 'red', // Light tick labels
                        font: {
                            size: 12,
                            family: "'Roboto', sans-serif",
                        },
                        autoSkip: true,
                        maxRotation: 45, // Ensures the labels aren't too long
                        minRotation: 0,
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'number of alerts',
                        font: {
                            size: 16
                        }
                    },
                    beginAtZero: true,
                    grid: {
                        color: '#ccc', // Light grid lines
                    },
                    ticks: {
                        color: 'red', // Light tick labels
                        font: {
                            size: 12,
                            family: "'Roboto', sans-serif",
                        },
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top', // Position legend at the top
                    labels: {
                        color: '#ccc', // Legend color
                        font: {
                            size: 14,
                            family: "'Roboto', sans-serif",
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Security Alerts Dashboard - Real-time Monitoring',
                    color: '#ccd',
                    font: {
                        size: 18,
                        family: "'Roboto', sans-serif",
                        weight: 'bold',
                    },
                    padding: {
                        top: 10,
                        bottom: 30
                    }
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#fff',
                    borderColor: '#ffffff',
                    borderWidth: 1,
                    cornerRadius: 4,
                    callbacks: {
                        label: function (context) {
                            var label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.raw !== null) {
                                label += context.raw;
                            }
                            return label;
                        }
                    }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutCubic',
            },
            elements: {
                line: {
                    borderWidth: 3, // Thicker lines
                    tension: 0.4 // Smooth curves between points
                },
                point: {
                    radius: 4,
                    hitRadius: 10, // Larger area for clicking/hovering
                    hoverRadius: 6
                }
            }
        }
    });

    // Function to fetch and update the alert counts
    function fetchAlertCounts() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'get_alert_counts.php', true); // Adjust to the correct PHP endpoint
        xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                var response = JSON.parse(xhr.responseText);
                var alertCounts = response.alert_counts;

                // Get current time as label
                var now = new Date().toLocaleTimeString();
                alertsChart.data.labels.push(now);

                // Add new data points to each dataset
                alertsChart.data.datasets[0].data.push(alertCounts.suspicious_behavior || 0);
                alertsChart.data.datasets[1].data.push(alertCounts.suspicious_files || 0);
                alertsChart.data.datasets[2].data.push(alertCounts.detected_vulnerabilities || 0);
                alertsChart.data.datasets[3].data.push(alertCounts.suspicious_traffic || 0);
                alertsChart.data.datasets[4].data.push(alertCounts.suspicious_emails || 0);

                // Keep chart manageable (e.g., keep the last 10 points)
                if (alertsChart.data.labels.length > 10) {
                    alertsChart.data.labels.shift(); // Remove first label
                    alertsChart.data.datasets.forEach(dataset => dataset.data.shift()); // Remove first data point for each dataset
                }

                // Update the chart to display new data
                alertsChart.update();
            } else {
                console.error('Failed to load alert counts:', xhr.statusText);
            }
        };
        xhr.onerror = function () {
            console.error('Request error.');
        };
        xhr.send();
    }

    // Ensure that chart data is only cleared when necessary
    function resetChartIfNoData() {
        var noData = alertsChart.data.datasets.every(dataset => dataset.data.length === 0);
        if (noData) {
            // Clear labels and data only if no data exists
            alertsChart.data.labels = [];
            alertsChart.data.datasets.forEach(dataset => dataset.data = []);
        }
    }

    // Initial empty graph display
    function displayEmptyGraph() {
        // Ensure there are at least empty labels and data to display
        alertsChart.data.labels = ['Initial'];
        alertsChart.data.datasets.forEach(dataset => dataset.data = [0]);
        alertsChart.update();
    }

    // Display the empty graph initially
    displayEmptyGraph();

    // Fetch alert counts every 30 seconds
    setInterval(() => {
        resetChartIfNoData();
        fetchAlertCounts();
    }, 10000);

    // Initial fetch
    fetchAlertCounts();



});