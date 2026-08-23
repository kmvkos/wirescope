async function checkStatus() {

    const element =
        document.getElementById("system-status");

    try {

        const response =
            await fetch("/api/status");

        if (!response.ok) {
            throw new Error();
        }

        element.textContent = "READY";
        element.className = "status online";

    } catch {

        element.textContent = "ERROR";
        element.className = "status offline";

    }
}


async function loadEnvironment() {

    try {

        const response =
            await fetch("/api/environment");

        const data =
            await response.json();


        document.getElementById("hostname")
            .textContent =
            data.hostname || "—";


        const interfaces =
            data.interfaces || [];


        /*
         * Пока автоматически берём первый
         * non-loopback интерфейс.
         *
         * Позже GUI позволит выбирать NIC.
         */

        const iface =
            interfaces.length > 0
                ? interfaces[0]
                : null;


        if (iface) {

            document.getElementById("interface")
                .textContent =
                iface.name || "—";


            document.getElementById("link")
                .textContent =
                iface.state || "—";


            document.getElementById("mac")
                .textContent =
                iface.mac || "—";


            document.getElementById("mtu")
                .textContent =
                iface.mtu || "—";


            document.getElementById("speed")
                .textContent =
                iface.speed_mbps
                    ? `${iface.speed_mbps} Mbps`
                    : "Unknown";


            document.getElementById("ipv4")
                .textContent =
                iface.ipv4.length
                    ? iface.ipv4.join(", ")
                    : "No IPv4";

        }


        const route =
            data.default_route;


        document.getElementById("gateway")
            .textContent =
            route && route.gateway
                ? route.gateway
                : "None";


        const dns =
            data.dns || [];


        document.getElementById("dns")
            .textContent =
            dns.length
                ? dns.join(", ")
                : "Not detected";


    } catch (error) {

        console.error(
            "Environment discovery failed:",
            error
        );

    }
}


checkStatus();
loadEnvironment();
