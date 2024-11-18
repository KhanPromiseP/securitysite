
document.addEventListener('DOMContentLoaded', function () {
    var ctx = document.getElementById('alertsChart').getContext('2d');


    var alertsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [], 
            datasets: [
                {
                    label: 'network_logs',
                    data: [], 
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderWidth: 2,
                    pointStyle: 'circle',
                    pointRadius: 4, 
                    pointHoverRadius: 6,
                    fill: true, 
                    tension: 0.4 
                },
                {
                    label: 'website_logs',
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
                        color: '#ccc', 
                    },
                    ticks: {
                        color: 'red',
                        font: {
                            size: 12,
                            family: "'Roboto', sans-serif",
                        },
                        autoSkip: true,
                        maxRotation: 45,
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
                        color: '#ccc', 
                    },
                    ticks: {
                        color: 'red', 
                        font: {
                            size: 12,
                            family: "'Roboto', sans-serif",
                        },
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top', 
                    labels: {
                        color: '#ccc', 
                        font: {
                            size: 14,
                            family: "'Roboto', sans-serif",
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Security Network Vs Website Results',
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
                    borderWidth: 3,
                    tension: 0.4 
                },
                point: {
                    radius: 4,
                    hitRadius: 10, 
                    hoverRadius: 6
                }
            }
        }
    });

    /**
     * Function to fetch and update the alert counts
     */ 
    function fetchAlertCounts() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '../logic/get_alert_counts.php', true); 
        xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                var response = JSON.parse(xhr.responseText);
                var alertCounts = response.alert_counts;

                var now = new Date().toLocaleTimeString();
                alertsChart.data.labels.push(now);

                alertsChart.data.datasets[0].data.push(alertCounts.network_logs || 0);
                alertsChart.data.datasets[1].data.push(alertCounts.website_logs || 0);
             
                if (alertsChart.data.labels.length > 10) {
                    alertsChart.data.labels.shift(); 
                    alertsChart.data.datasets.forEach(dataset => dataset.data.shift()); 
                }

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

    
    function resetChartIfNoData() {
        var noData = alertsChart.data.datasets.every(dataset => dataset.data.length === 0);
        if (noData) {
         
            alertsChart.data.labels = [];
            alertsChart.data.datasets.forEach(dataset => dataset.data = []);
        }
    }


    function displayEmptyGraph() {
    
        alertsChart.data.labels = ['Initial'];
        alertsChart.data.datasets.forEach(dataset => dataset.data = [0]);
        alertsChart.update();
    }

    displayEmptyGraph();

    setInterval(() => {
        resetChartIfNoData();
        fetchAlertCounts();
    }, 10000);

  
    fetchAlertCounts();



});