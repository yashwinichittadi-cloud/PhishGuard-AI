/**
 * PhishGuard AI - Chart.js Visualizations
 * Renders threat intelligence distributions, daily telemetry, and ML benchmarks.
 */

let classificationChartInstance = null;
let riskDistChartInstance = null;
let dailyActivityChartInstance = null;
let modelComparisonChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("classificationDonutChart")) {
        window.renderDashboardCharts();
    }
    if (document.getElementById("modelComparisonChart")) {
        window.renderPerformanceCharts();
    }
});

function getThemePalette() {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    return {
        textColor: isLight ? "#475569" : "#94a3b8",
        gridColor: isLight ? "rgba(148, 163, 184, 0.2)" : "rgba(56, 189, 248, 0.08)",
        tooltipBg: isLight ? "#ffffff" : "#0f172a",
        tooltipText: isLight ? "#0f172a" : "#f8fafc",
        borderColor: isLight ? "#cbd5e1" : "rgba(56, 189, 248, 0.2)"
    };
}

/* ==========================================================================
   1. Dashboard Charts Orchestration
   ========================================================================== */
window.renderDashboardCharts = async function() {
    try {
        const res = await fetch("/api/dashboard/stats");
        const stats = await res.json();
        const palette = getThemePalette();

        // 1. Classification Donut Chart
        const donutCtx = document.getElementById("classificationDonutChart")?.getContext("2d");
        if (donutCtx) {
            if (classificationChartInstance) classificationChartInstance.destroy();
            classificationChartInstance = new Chart(donutCtx, {
                type: "doughnut",
                data: {
                    labels: stats.classification_chart.labels,
                    datasets: [{
                        data: stats.classification_chart.data,
                        backgroundColor: stats.classification_chart.colors,
                        borderWidth: 2,
                        borderColor: palette.tooltipBg,
                        hoverOffset: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: { color: palette.textColor, font: { family: "Inter", size: 12 } }
                        }
                    },
                    cutout: "70%"
                }
            });
        }

        // 2. Risk Distribution Bar Chart
        const barCtx = document.getElementById("riskDistributionBarChart")?.getContext("2d");
        if (barCtx) {
            if (riskDistChartInstance) riskDistChartInstance.destroy();
            riskDistChartInstance = new Chart(barCtx, {
                type: "bar",
                data: {
                    labels: stats.risk_distribution_chart.labels,
                    datasets: [{
                        label: "Scans",
                        data: stats.risk_distribution_chart.data,
                        backgroundColor: [
                            "rgba(16, 185, 129, 0.8)",
                            "rgba(52, 211, 153, 0.8)",
                            "rgba(245, 158, 11, 0.8)",
                            "rgba(251, 146, 60, 0.8)",
                            "rgba(239, 68, 68, 0.8)"
                        ],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: palette.textColor, font: { size: 10 } }
                        },
                        y: {
                            grid: { color: palette.gridColor },
                            ticks: { color: palette.textColor, stepSize: 1 }
                        }
                    }
                }
            });
        }

        // 3. Daily Scanning Activity Line Chart
        const lineCtx = document.getElementById("dailyActivityLineChart")?.getContext("2d");
        if (lineCtx) {
            if (dailyActivityChartInstance) dailyActivityChartInstance.destroy();
            dailyActivityChartInstance = new Chart(lineCtx, {
                type: "line",
                data: {
                    labels: stats.daily_activity_chart.labels,
                    datasets: [{
                        label: "URLs Audited",
                        data: stats.daily_activity_chart.data,
                        borderColor: "#38bdf8",
                        backgroundColor: "rgba(56, 189, 248, 0.15)",
                        borderWidth: 3,
                        fill: true,
                        tension: 0.35,
                        pointBackgroundColor: "#0284c7",
                        pointRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: palette.textColor }
                        },
                        y: {
                            grid: { color: palette.gridColor },
                            ticks: { color: palette.textColor, stepSize: 1 }
                        }
                    }
                }
            });
        }

    } catch (e) {
        console.error("Dashboard charts error:", e);
    }
};

/* ==========================================================================
   2. Model Performance Benchmarks Orchestration
   ========================================================================== */
window.renderPerformanceCharts = async function() {
    try {
        const res = await fetch("/api/model/metrics");
        const data = await res.json();
        const palette = getThemePalette();

        if (data.status !== "ready") return;

        const lr = data.models_evaluated.logistic_regression;
        const rf = data.models_evaluated.random_forest;

        const compareCtx = document.getElementById("modelComparisonChart")?.getContext("2d");
        if (compareCtx) {
            if (modelComparisonChartInstance) modelComparisonChartInstance.destroy();
            modelComparisonChartInstance = new Chart(compareCtx, {
                type: "bar",
                data: {
                    labels: ["Accuracy", "Precision", "Recall", "F1-Score"],
                    datasets: [
                        {
                            label: "Logistic Regression",
                            data: [lr.accuracy * 100, lr.precision * 100, lr.recall * 100, lr.f1 * 100],
                            backgroundColor: "rgba(56, 189, 248, 0.75)",
                            borderRadius: 6
                        },
                        {
                            label: "Random Forest Classifier",
                            data: [rf.accuracy * 100, rf.precision * 100, rf.recall * 100, rf.f1 * 100],
                            backgroundColor: "rgba(16, 185, 129, 0.75)",
                            borderRadius: 6
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "top",
                            labels: { color: palette.textColor, font: { family: "Inter", size: 12 } }
                        },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => `${ctx.dataset.label}: ${ctx.raw.toFixed(1)}%`
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: palette.textColor }
                        },
                        y: {
                            min: 80,
                            max: 100,
                            grid: { color: palette.gridColor },
                            ticks: {
                                color: palette.textColor,
                                callback: (v) => `${v}%`
                            }
                        }
                    }
                }
            });
        }

    } catch (e) {
        console.error("Performance charts error:", e);
    }
};
