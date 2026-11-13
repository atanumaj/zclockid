        // Initialize dashboard and telemetry polling
        document.addEventListener('DOMContentLoaded', async () => {
            const urlParams = new URLSearchParams(window.location.search);
            const targetTab = urlParams.get('tab') || (window.location.hash || '').replace('#', '') || 'dashboard';

            // 1. Asynchronously load modals and active tab
            await Promise.all([loadModals(), ensureTabLoaded(targetTab)]);
            if (targetTab !== 'dashboard' && typeof showTab === 'function') {
                showTab(targetTab);
            }

            // 2. Initialize application state, navigation, and telemetry pollers
            initSessionInfo();
            initRsatGuideState();
            initSecurityNavGroupState();
            fetchSystemStatus();
            fetchAuthStats24h();
            fetchDomainInfo();
            fetchRadiusBandwidth();
            setInterval(fetchSystemStatus, 5000);
            setInterval(fetchAuthStats24h, 30000);

            // 3. Background preload remaining tabs during browser idle time
            if ('requestIdleCallback' in window) {
                requestIdleCallback(() => preloadAllTabs());
            } else {
                setTimeout(preloadAllTabs, 200);
            }
        });
