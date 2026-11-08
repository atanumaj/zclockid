        // Initialize dashboard and telemetry polling
        document.addEventListener('DOMContentLoaded', () => {
            initSessionInfo();
            initRsatGuideState();
            initSecurityNavGroupState();
            fetchSystemStatus();
            fetchAuthStats24h();
            fetchDomainInfo();
            fetchRadiusBandwidth();
            setInterval(fetchSystemStatus, 5000);
            setInterval(fetchAuthStats24h, 30000);
        });
